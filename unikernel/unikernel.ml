(* (c) 2020 Hannes Mehnert, all rights reserved *)

(* left to do:
   - statistics (metrics)
   - haproxy1 support (PROXY TCP4|6 SOURCEIP DESTIP SRCPORT DESTPORT\r\n) at the beginning of the TCP connection to the backend
   - NG: apart from SNI allow other ports to be redirected (no proxy)
*)

open Lwt.Infix

module Main (R : Mirage_random.S) (T : Mirage_time.S) (Pclock : Mirage_clock.PCLOCK) (Block : Mirage_block.S) (Public : Tcpip.Stack.V4V6) (Private : Tcpip.Stack.V4V6) = struct
  module FS = Filesystem.Make(Pclock)(Block)

  type config = {
    mutable superblock : FS.superblock ;
    mutable sni : (Ipaddr.t * int) Domain_name.Host_map.t ;
  }

  let read_configuration block =
    FS.read_data block >>= function
    | Error `Bad_checksum ->
      (FS.init block >>= function
        | Ok superblock ->
          Lwt.return { superblock ; sni = Domain_name.Host_map.empty }
        | Error `Msg e ->
          Logs.err (fun m -> m "error initializing the block device %s" e);
          Lwt.fail_with "initializing block device")
    | Error `Msg msg ->
      Logs.err (fun m -> m "error reading block device %s" msg);
      Lwt.fail_with "reading block device"
    | Error (#FS.decode_err as e) ->
      Logs.err (fun m -> m "error reading block device %a" FS.pp_decode_err e);
      Lwt.fail_with "reading block device"
    | Ok (superblock, data) ->
      Logs.info (fun m -> m "read from %a (counter %u) %u bytes data"
                    (Ptime.pp_rfc3339 ()) superblock.FS.timestamp
                    superblock.FS.super_counter
                    superblock.FS.data_length);
      let config = { superblock ; sni = Domain_name.Host_map.empty } in
      if Cstruct.length data > 0 then begin
        let sni = Configuration.decode_data data in
        config.sni <- sni;
      end;
      Logs.info (fun m -> m "SNI map has %d entries"
                    (Domain_name.Host_map.cardinal config.sni));
      Lwt.return config

  let write_configuration block config =
    let open Lwt_result.Infix in
    let data = Configuration.encode_data config.sni in
    FS.write_data block config.superblock data >|= fun superblock ->
    config.superblock <- superblock

  let handle_config block config cmd =
    match cmd with
    | Configuration.Add (sni, host, port) ->
      begin
        let snis = Configuration.add_sni config.sni (sni, host, port) in
        config.sni <- snis;
        write_configuration block config >|= function
        | Ok () ->
          let msg =
            Format.asprintf "%a was successfully added" Domain_name.pp sni
          in
          Configuration.Result (0, msg)
        | Error `Msg m ->
          let msg = Format.asprintf "error %s adding %a" m Domain_name.pp sni in
          Configuration.Result (1, msg)
      end
    | Configuration.Remove sni ->
      begin
        let snis = Configuration.remove_sni config.sni sni in
        config.sni <- snis;
        write_configuration block config >|= function
        | Ok () ->
          let msg =
            Format.asprintf "%a was successfylly removed" Domain_name.pp sni
          in
          Configuration.Result (0, msg)
        | Error `Msg m ->
          let msg =
            Format.asprintf "error %s removing %a" m Domain_name.pp sni
          in
          Configuration.Result (1, msg)
      end
    | Configuration.List ->
      let snis =
        Domain_name.Host_map.fold
          (fun sni (host, port) acc -> (sni, host, port) :: acc)
          config.sni []
      in
      Lwt.return (Configuration.Snis snis)
    | _ ->
      Lwt.return (Configuration.Result (1, "unexpected"))

  let handle_command block config data =
    (match Configuration.cmd_of_cs data with
     | Ok cmd -> handle_config block config cmd
     | Error `Msg err -> Lwt.return (Configuration.Result (2, err))) >|= fun reply ->
    Configuration.cmd_to_cs reply

  module H = Mirage_crypto.Hash.SHA256

  let auth key data =
    if Cstruct.length data > H.digest_size then
      let auth, data = Cstruct.split data H.digest_size in
      if Cstruct.equal (H.hmac ~key data) auth then
        Some data
      else
        None
    else
      None

  let config_cmd block config key data =
    match auth key data with
    | None -> Lwt.return (Configuration.cmd_to_cs (Configuration.Result (3, "authentication failure")))
    | Some data -> handle_command block config data

  let config_change block config key tcp =
    (Private.TCP.read tcp >>= function
      | Error e ->
        Logs.err (fun m -> m "config TCP read error %a" Private.TCP.pp_error e);
        Lwt.return_unit
      | Ok `Eof ->
        Logs.warn (fun m -> m "config TCP read eof");
        Lwt.return_unit
      | Ok `Data buf ->
        let buf' = Cstruct.shift buf 8 in
        let l = Cstruct.BE.get_uint64 buf 0 in
        if Cstruct.length buf' = Int64.to_int l then
          config_cmd block config key buf' >>= fun res ->
          let size = Cstruct.create 8 in
          Cstruct.BE.set_uint64 size 0 (Int64.of_int (Cstruct.length res));
          Private.TCP.write tcp (Cstruct.append size res) >|= function
          | Ok () -> ()
          | Error e ->
            Logs.warn (fun m -> m "config TCP write error %a" Private.TCP.pp_write_error e)
        else begin
          Logs.warn (fun m -> m "truncated config message");
          Lwt.return_unit
        end)
    >>= fun () ->
    Private.TCP.close tcp

  module TLS = Tls_mirage.Make(Public.TCP)

  let extract_location content =
    (* we assume a HTTP request in here, and want to reply with a moved
       permanently (301) carrying a location header of the form
       Location: https://<host>/<url>
       So we decode the incoming read data for
       (a) "HTTP method" "URL" (anything else)
       (b) "Host:" <data> header *)
    match Astring.String.cuts ~sep:"\r\n" content with
    | request :: headers ->
      begin
        match
          Astring.String.cuts ~sep:" " request,
          List.find_opt (fun x ->
              Astring.String.is_prefix ~affix:"host:"
                (Astring.String.Ascii.lowercase x))
            headers
        with
        | _method :: url :: _, Some host ->
          begin match Astring.String.cut ~sep:":" host with
            | Some (_, host) ->
              let loc = ["https://" ; Astring.String.trim host ; url ] in
              Some (String.concat "" loc)
            | None ->
              Logs.warn (fun m -> m "no name in host header %S" host);
              None
          end
        | _ ->
          Logs.warn (fun m -> m "no url or host header found in %S" content);
          None
      end
    | [] ->
      Logs.warn (fun m -> m "no http header found in %S" content);
      None

  let redirect tcp =
    Public.TCP.read tcp >>= fun data ->
    let reply = match data with
      | Error e ->
        Logs.err (fun m -> m "TCP error %a" Public.TCP.pp_error e);
        None
      | Ok `Eof ->
        Logs.err (fun m -> m "TCP eof");
        None
      | Ok `Data data ->
        (* this is slighly brittle since it only uses the first bytes read() *)
        extract_location (Cstruct.to_string data)
    in
    (match reply with
     | None -> Lwt.return_unit
     | Some data ->
       let reply =
         let status = "HTTP/1.1 301 Moved permanently"
         and location = "Location: " ^ data
         and content_len = "Content-Length: 0"
         and server = "Server: OCaml TLStunnel"
         in
         String.concat "\r\n" [ status ; location ; content_len ; server ; "" ; "" ]
       in
       Public.TCP.write tcp (Cstruct.of_string reply) >|= function
       | Ok () -> ()
       | Error e ->
         Logs.err (fun m -> m "error %a sending redirect" Public.TCP.pp_write_error e))
    >>= fun () ->
    Public.TCP.close tcp

  let close tls tcp =
    Private.TCP.close tcp >>= fun () ->
    TLS.close tls

  let rec read_tls_write_tcp tls tcp =
    TLS.read tls >>= function
    | Error e ->
      Logs.err (fun m -> m "TLS read error %a" TLS.pp_error e);
      close tls tcp
    | Ok `Eof -> close tls tcp
    | Ok `Data buf ->
      Private.TCP.write tcp buf >>= function
      | Error e ->
        Logs.err (fun m -> m "TCP write error %a" Private.TCP.pp_write_error e);
        close tls tcp
      | Ok () ->
        read_tls_write_tcp tls tcp

  let rec read_tcp_write_tls tcp tls =
    Private.TCP.read tcp >>= function
    | Error e ->
      Logs.err (fun m -> m "TCP read error %a" Private.TCP.pp_error e);
      close tls tcp
    | Ok `Eof -> close tls tcp
    | Ok `Data buf ->
      TLS.write tls buf >>= function
      | Error e ->
        Logs.err (fun m -> m "TLS write error %a" TLS.pp_write_error e);
        close tls tcp
      | Ok () ->
        read_tcp_write_tls tcp tls

  let default_host = Domain_name.(host_exn (of_string_exn "default"))

  let tls_accept priv config tls_config tcp_flow =
    (* TODO this should timeout the TLS handshake with a reasonable timer *)
    TLS.server_of_flow tls_config tcp_flow >>= function
    | Error e ->
      Logs.warn (fun m -> m "TLS error %a" TLS.pp_write_error e);
      Public.TCP.close tcp_flow
    | Ok tls_flow ->
      let close () =
        TLS.close tls_flow
      in
      match TLS.epoch tls_flow with
      | Ok epoch ->
        begin
          let default () =
            Domain_name.Host_map.find_opt default_host config.sni
          in
          match
            match epoch.Tls.Core.own_name with
            | None ->
              Logs.warn (fun m -> m "no server name specified");
              default ()
            | Some sni ->
              match Domain_name.Host_map.find_opt sni config.sni with
              | None ->
                Logs.warn (fun m -> m "server name %a not configured"
                              Domain_name.pp sni);
                default ()
              | Some (host, port) -> Some (host, port)
          with
          | None -> close ()
          | Some (host, port) ->
            Private.TCP.create_connection priv (host, port) >>= function
            | Error e ->
              Logs.err (fun m -> m "error %a connecting to backend"
                           Private.TCP.pp_error e);
              close ()
            | Ok tcp_flow ->
              Lwt.join [
                read_tls_write_tcp tls_flow tcp_flow ;
                read_tcp_write_tls tcp_flow tls_flow
              ]
        end
      | Error () ->
        Logs.warn (fun m -> m "unexpected error retrieving the TLS session");
        close ()

  module D = Dns_certify_mirage.Make(R)(Pclock)(T)(Public)

  let start _ () () block pub priv =
    read_configuration block >>= fun config ->
    Private.TCP.listen (Private.tcp priv) ~port:(Key_gen.configuration_port ())
      (config_change block config (Cstruct.of_string (Key_gen.key ())));
    let domains = Key_gen.domains ()
    and key_seed = Key_gen.key_seed ()
    and dns_key = Key_gen.dns_key ()
    and dns_server = Key_gen.dns_server ()
    in
    Public.TCP.listen (Public.tcp pub) ~port:80 redirect;
    let rec retrieve_certs () =
      Lwt_list.fold_left_s (fun acc domain ->
          let key_seed = domain ^ ":" ^ key_seed in
          D.retrieve_certificate pub ~dns_key
            ~hostname:Domain_name.(host_exn (of_string_exn domain))
            ~additional_hostnames:[ Domain_name.of_string_exn ("*." ^ domain) ]
            ~key_seed dns_server 53 >>= function
          | Error `Msg err -> Lwt.fail_with err
          | Ok certificates -> Lwt.return (certificates :: acc))
        [] domains >>= fun cert_chains ->
      (match List.rev cert_chains with
       | [] -> Lwt.fail_with "empty certificate chains"
       | a :: _ -> Lwt.return a) >>= fun first ->
      let certificates = `Multiple_default (first, cert_chains) in
      let tls_config = Tls.Config.server ~certificates () in
      let priv_tcp = Private.tcp priv in
      let port = Key_gen.frontend_port () in
      Public.TCP.listen (Public.tcp pub) ~port (tls_accept priv_tcp config tls_config);
      let now = Ptime.v (Pclock.now_d_ps ()) in
      let seven_days_before_expire =
        let next_expire =
          let expiring =
            List.map snd
              (List.map X509.Certificate.validity
                 (List.map (function (s::_, _) -> s | _ -> assert false)
                      cert_chains))
          in
          let diffs = List.map (fun exp -> Ptime.diff exp now) expiring in
          let closest_span = List.hd (List.sort Ptime.Span.compare diffs) in
          fst (Ptime.Span.to_d_ps closest_span)
        in
        max (Duration.of_hour 1) (Duration.of_day (max 0 (next_expire - 7)))
      in
      T.sleep_ns seven_days_before_expire >>= fun () ->
      retrieve_certs ()
    in
    retrieve_certs ()
end
