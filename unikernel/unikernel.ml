(* (c) 2020 Hannes Mehnert, all rights reserved *)

(* left to do:
   - haproxy1 support (PROXY TCP4|6 SOURCEIP DESTIP SRCPORT DESTPORT\r\n) at the beginning of the TCP connection to the backend
   - NG: apart from SNI allow other ports to be redirected (no proxy)
*)

module K = struct
  open Cmdliner

  let host =
    Arg.conv ~docv:"HOSTNAME"
      ((fun s -> Result.bind (Domain_name.of_string s) Domain_name.host),
       Domain_name.pp)

  let key_v =
    Arg.conv ~docv:"HOST:HASH:DATA"
      Dns.Dnskey.(name_key_of_string,
                  (fun ppf v -> Fmt.string ppf (name_key_to_string v)))

  let frontend_port =
    let doc = Arg.info ~doc:"The TCP port of the frontend." ["frontend-port"] in
    Mirage_runtime.register_arg Arg.(value & opt int 443 doc)

  let key =
    let doc = Arg.info ~doc:"The shared secret" ["key"] in
    Mirage_runtime.register_arg Arg.(required & opt (some string) None doc)

  let configuration_port =
    let doc = Arg.info ~doc:"The TCP port for configuration." ["configuration-port"] in
    Mirage_runtime.register_arg Arg.(value & opt int 1234 doc)

  let dns_key =
    let doc = Arg.info ~doc:"nsupdate key" ["dns-key"] in
    Mirage_runtime.register_arg Arg.(required & opt (some key_v) None doc)

  let dns_server =
    let doc = Arg.info ~doc:"dns server IP" ["dns-server"] in
    Mirage_runtime.register_arg
      Arg.(required & opt (some Mirage_runtime_network.Arg.ip_address) None doc)

  let domains =
    let doc = Arg.info ~doc:"domains" ["domains"] in
    Mirage_runtime.register_arg Arg.(value & opt_all host [] doc)

  let key_seed =
    let doc = Arg.info ~doc:"certificate key seed" ["key-seed"] in
    Mirage_runtime.register_arg Arg.(required & opt (some string) None doc)
end

open Lwt.Infix

module Main (Block : Mirage_block.S) (Public : Tcpip.Stack.V4V6) (Private : Tcpip.Stack.V4V6) = struct
  let snis =
    let create ~f =
      let data : (string, int) Hashtbl.t = Hashtbl.create 7 in
      (fun x ->
         let key = f x in
         let cur = match Hashtbl.find_opt data key with
           | None -> 0
           | Some x -> x
         in
         Hashtbl.replace data key (succ cur)),
      (fun () ->
         let data, total =
           Hashtbl.fold (fun key value (acc, total) ->
               (Metrics.uint key value :: acc), value + total)
             data ([], 0)
         in
         Metrics.uint "total" total :: data)
    in
    let src =
      let open Metrics in
      let doc = "Counter metrics" in
      let incr, get = create ~f:Fun.id in
      let data thing = incr thing; Data.v (get ()) in
      Src.v ~doc ~tags:Metrics.Tags.[] ~data "tlstunnel"
    in
    (fun r -> Metrics.add src (fun x -> x) (fun d -> d r))

  let access kind =
    let s = ref (0, 0) in
    let open Metrics in
    let doc = "connection statistics" in
    let data () =
      Data.v [
        int "active" (fst !s) ;
        int "total" (snd !s) ;
      ] in
    let tags = Tags.string "kind" in
    let src = Src.v ~doc ~tags:Tags.[ tags ] ~data "connections" in
    (fun action ->
       (match action with
        | `Open -> s := (succ (fst !s), succ (snd !s))
        | `Close -> s := (pred (fst !s), snd !s));
       Metrics.add src (fun x -> x kind) (fun d -> d ()))

  let frontend_access = access "frontend"
  let tls_access = access "tls"
  let config_access = access "config"
  let http_access = access "http"
  let backend_access = access "backend"

  module FS = Filesystem.Make(Block)

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
      if String.length data > 0 then begin
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
    (match Configuration.cmd_of_str data with
     | Ok cmd -> handle_config block config cmd
     | Error `Msg err -> Lwt.return (Configuration.Result (2, err))) >|= fun reply ->
    Configuration.cmd_to_str reply

  module H = Digestif.SHA256

  let auth key data =
    if String.length data > H.digest_size then
      let auth, data =
        String.sub data 0 H.digest_size,
        String.sub data H.digest_size (String.length data - H.digest_size)
      in
      if String.equal H.(to_raw_string (hmac_string ~key data)) auth then
        Some data
      else
        None
    else
      None

  let config_cmd block config key data =
    match auth key data with
    | None -> Lwt.return (Configuration.cmd_to_str (Configuration.Result (3, "authentication failure")))
    | Some data -> handle_command block config data

  let config_change block config key tcp =
    config_access `Open;
    (Private.TCP.read tcp >>= function
      | Error e ->
        Logs.err (fun m -> m "config TCP read error %a" Private.TCP.pp_error e);
        Lwt.return_unit
      | Ok `Eof ->
        Logs.warn (fun m -> m "config TCP read eof");
        Lwt.return_unit
      | Ok `Data buf ->
        let buf' = Cstruct.to_string ~off:8 buf in
        let l = Cstruct.BE.get_uint64 buf 0 in
        if String.length buf' = Int64.to_int l then
          config_cmd block config key buf' >>= fun res ->
          let buf = Cstruct.create (8 + String.length res) in
          Cstruct.BE.set_uint64 buf 0 (Int64.of_int (String.length res));
          Cstruct.blit_from_string res 0 buf 8 (String.length res);
          Private.TCP.write tcp buf >|= function
          | Ok () -> ()
          | Error e ->
            Logs.warn (fun m -> m "config TCP write error %a" Private.TCP.pp_write_error e)
        else begin
          Logs.warn (fun m -> m "truncated config message");
          Lwt.return_unit
        end)
    >>= fun () ->
    config_access `Close;
    Private.TCP.close tcp

  module TLS = Tls_mirage.Make(Public.TCP)

  let extract_location content =
    (* we assume a HTTP request in here, and want to reply with a moved
       permanently (301) carrying a location header of the form
       Location: https://<host>/<url>
       So we decode the incoming read data for
       (a) "HTTP method" "URL" (anything else)
       (b) "Host:" <data> header *)
    match List.map String.trim (String.split_on_char '\n' content) with
    | request :: headers ->
      begin
        match
          String.split_on_char ' ' request,
          List.find_opt (fun x ->
              String.length x >= 5 &&
              String.sub (String.lowercase_ascii x) 0 5 = "host:")
            headers
        with
        | _method :: url :: _, Some host ->
          begin match String.split_on_char ':' host with
            | _hdr :: host_els ->
              let host = String.concat ":" host_els in
              let loc = ["https://" ; String.trim host ; url ] in
              Some (String.concat "" loc)
            | _ ->
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

  let http_reply ?(body = "") ?(headers = []) ~status_code status =
    let status = Printf.sprintf "HTTP/1.1 %u %s" status_code status
    and headers =
      "Server: OCaml TLStunnel" ::
      Printf.sprintf "Content-Length: %u" (String.length body) ::
      (if body = "" then [] else [ "Content-Type: text/plain; charset=utf-8" ]) @
      headers
    in
    String.concat "\r\n" (status :: headers @ [ "" ; body ])

  let redirect tcp =
    http_access `Open;
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
         http_reply ~headers:[ "Location: " ^ data ] ~status_code:301
           "Moved permanently"
       in
       Public.TCP.write tcp (Cstruct.of_string reply) >|= function
       | Ok () -> ()
       | Error e ->
         Logs.err (fun m -> m "error %a sending redirect" Public.TCP.pp_write_error e))
    >>= fun () ->
    http_access `Close;
    Public.TCP.close tcp

  let close tls tcp =
    tls_access `Close;
    frontend_access `Close;
    backend_access `Close;
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
    frontend_access `Open;
    (* TODO this should timeout the TLS handshake with a reasonable timer *)
    TLS.server_of_flow tls_config tcp_flow >>= function
    | Error e ->
      Logs.warn (fun m -> m "TLS error %a" TLS.pp_write_error e);
      frontend_access `Close;
      Public.TCP.close tcp_flow
    | Ok tls_flow ->
      tls_access `Open;
      let close () =
        tls_access `Close;
        frontend_access `Close;
        TLS.close tls_flow >>= fun () ->
        Public.TCP.close tcp_flow
      in
      match TLS.epoch tls_flow with
      | Ok epoch ->
        begin
          let sni, sni_text =
            let default () =
              Domain_name.Host_map.find_opt default_host config.sni
            in
            match epoch.Tls.Core.own_name with
            | None ->
              snis "no sni";
              default (), "no sni"
            | Some sni ->
              let r =
                match Domain_name.Host_map.find_opt sni config.sni with
                | None ->
                  Logs.warn (fun m -> m "server name %a not configured"
                                Domain_name.pp sni);
                  default ()
                | Some (host, port) ->
                  snis (Domain_name.to_string sni);
                  Some (host, port)
              in
              r, Domain_name.to_string sni
          in
          match sni with
          | None ->
            let reply =
              http_reply
                ~body:("Couldn't figure which service you want ('" ^ sni_text ^ "'), and no default is configured")
                ~status_code:404 "Not Found"
            in
            TLS.write tls_flow (Cstruct.of_string reply) >>= fun _ ->
            close ()
          | Some (host, port) ->
            Private.TCP.create_connection priv (host, port) >>= function
            | Error e ->
              Logs.err (fun m -> m "error %a connecting to backend"
                           Private.TCP.pp_error e);
              let reply =
                http_reply
                  ~body:("Couldn't connect to backend service for '" ^ sni_text ^ "', please come back later")
                  ~status_code:502 "Bad gateway"
              in
              TLS.write tls_flow (Cstruct.of_string reply) >>= fun _ ->
              close ()
            | Ok tcp_flow ->
              backend_access `Open;
              Lwt.pick [
                read_tls_write_tcp tls_flow tcp_flow ;
                read_tcp_write_tls tcp_flow tls_flow
              ] >>= fun () ->
              close () >>= fun () ->
              Private.TCP.close tcp_flow
        end
      | Error () ->
        Logs.warn (fun m -> m "unexpected error retrieving the TLS session");
        close ()

  module D = Dns_certify_mirage.Make(Public)

  let start block pub priv =
    read_configuration block >>= fun config ->
    Private.TCP.listen (Private.tcp priv) ~port:(K.configuration_port ())
      (config_change block config (K.key ()));
    Public.TCP.listen (Public.tcp pub) ~port:80 redirect;
    let rec retrieve_certs () =
      Lwt_list.fold_left_s (fun acc domain ->
          let key_seed = Domain_name.to_string domain ^ ":" ^ (K.key_seed ()) in
          D.retrieve_certificate pub (K.dns_key ())
            ~hostname:domain
            ~additional_hostnames:[ Domain_name.(append_exn (of_string_exn "*") domain) ]
            ~key_seed (K.dns_server ()) 53 >>= function
          | Error `Msg err -> Lwt.fail_with err
          | Ok certificates -> Lwt.return (certificates :: acc))
        [] (K.domains ()) >>= fun cert_chains ->
      (match List.rev cert_chains with
       | [] -> failwith "empty certificate chains"
       | a :: _ -> Lwt.return a) >>= fun first ->
      let certificates = `Multiple_default (first, cert_chains) in
      match Tls.Config.server ~certificates () with
      | Error `Msg msg -> failwith msg
      | Ok tls_config ->
        let priv_tcp = Private.tcp priv in
        Public.TCP.listen (Public.tcp pub) ~port:(K.frontend_port ()) (tls_accept priv_tcp config tls_config);
        let now = Mirage_ptime.now () in
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
        Mirage_sleep.ns seven_days_before_expire >>= fun () ->
        retrieve_certs ()
    in
    retrieve_certs ()
end
