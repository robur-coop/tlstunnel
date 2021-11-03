let ( let* ) = Result.bind

let rec ign_intr f v =
  try f v with Unix.Unix_error (Unix.EINTR, _, _) -> ign_intr f v

let connect (host, port) =
  let connect () =
    try
      let sockaddr = Unix.ADDR_INET (host, port) in
      let s = Unix.(socket PF_INET SOCK_STREAM 0) in
      Unix.(connect s sockaddr);
      Ok s
    with
    | Unix.Unix_error (err, f, _) ->
      Logs.err (fun m -> m "unix error in %s: %s" f (Unix.error_message err));
      Error (`Msg "connect failure")
  in
  connect ()

let read fd =
  try
    let rec r b ?(off = 0) l =
      if l = 0 then
        Ok ()
      else
        let read = ign_intr (Unix.read fd b off) l in
        if read = 0 then
          Error (`Msg "end of file")
        else
          r b ~off:(read + off) (l - read)
    in
    let bl = Bytes.create 8 in
    let* () = r bl 8 in
    let l = Cstruct.BE.get_uint64 (Cstruct.of_bytes bl) 0 in
    let l_int = Int64.to_int l in (* TODO *)
    let b = Bytes.create l_int in
    let* () = r b l_int in
    Ok (Cstruct.of_bytes b)
  with
    Unix.Unix_error (err, f, _) ->
    Logs.err (fun m -> m "Unix error in %s: %s" f (Unix.error_message err));
    Error (`Msg "unix error in read")

let read_cmd fd =
  let* data = read fd in
  Configuration.cmd_of_cs data

let write fd data =
  try
    let rec w b ?(off = 0) l =
      if l = 0 then
        ()
      else
        let written = ign_intr (Unix.write fd b off) l in
        w b ~off:(written + off) (l - written)
    in
    let csl = Cstruct.create 8 in
    Cstruct.BE.set_uint64 csl 0 (Int64.of_int (Cstruct.length data));
    w (Cstruct.to_bytes (Cstruct.append csl data)) (Cstruct.length data + 8);
    Ok ()
  with
    Unix.Unix_error (err, f, _) ->
    Logs.err (fun m -> m "Unix error in %s: %s" f (Unix.error_message err));
    Error (`Msg "unix error in write")

module H = Mirage_crypto.Hash.SHA256

let write_cmd fd key cmd =
  let data = Configuration.cmd_to_cs cmd in
  let auth = H.hmac ~key:(Cstruct.of_string key) data in
  write fd (Cstruct.append auth data)

let write_read_print key remote cmd =
  let* s = connect remote in
  let* () = write_cmd s key cmd in
  let* cmd = read_cmd s in
  Unix.close s;
  Logs.app (fun m -> m "result: %a" Configuration.pp_cmd cmd);
  Ok ()

let list () key remote =
  write_read_print key remote Configuration.List

let add () key remote sni host port =
  write_read_print key remote (Configuration.Add (sni, host, port))

let remove () key remote sni =
  write_read_print key remote (Configuration.Remove sni)

let help () man_format cmds = function
  | None -> `Help (`Pager, None)
  | Some t when List.mem t cmds -> `Help (man_format, Some t)
  | Some x ->
    print_endline ("unknown command '" ^ x ^ "', available commands:");
    List.iter print_endline cmds;
    `Ok ()

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ~dst:Format.std_formatter ())

open Cmdliner

let host_port : (Unix.inet_addr * int) Arg.converter =
  let parse s =
    match String.split_on_char ':' s with
    | [ hostname ;  port ] ->
      begin try
          `Ok (Unix.inet_addr_of_string hostname, int_of_string port)
        with
          Not_found -> `Error "failed to parse IP:port"
      end
    | _ -> `Error "broken: no port specified"
  in
  parse, fun ppf (h, p) -> Format.fprintf ppf "%s:%d"
      (Unix.string_of_inet_addr h) p

let remote =
  let doc = "The remote host:port to connect to" in
  Arg.(value & opt host_port (Unix.inet_addr_loopback, 1234) &
       info [ "r" ; "remote" ] ~doc ~docv:"IP:PORT")

let key =
  let doc = "The shared secret" in
  Arg.(value & opt string "" & info [ "key" ] ~doc ~docv:"KEY")

let hn : [`host] Domain_name.t Arg.converter =
  let parse s =
    match Domain_name.of_string s with
    | Error `Msg m -> `Error m
    | Ok d -> match Domain_name.host d with
      | Error `Msg m -> `Error m
      | Ok h -> `Ok h
  in
  parse, Domain_name.pp

let sni =
  let doc = "The SNI." in
  Arg.(required & pos 0 (some hn) None & info [ ] ~doc ~docv:"SNI")

let setup_log =
  Term.(const setup_log
        $ Fmt_cli.style_renderer ()
        $ Logs_cli.level ())

let list_cmd =
  Term.(term_result (const list $ setup_log $ key $ remote)),
  Term.info "list"

let ip_conv : Ipaddr.t Arg.converter =
  let parse s =
    match Ipaddr.of_string  s with
    | Ok ip -> `Ok ip
    | Error `Msg msg -> `Error msg
  in
  parse, Ipaddr.pp

let ip =
  let doc = "The IP address." in
  Arg.(required & pos 1 (some ip_conv) None & info [] ~doc ~docv:"IP")

let port =
  let doc = "The port." in
  Arg.(required & pos 2 (some int) None & info [] ~doc ~docv:"PORT")

let add_cmd =
  Term.(term_result (const add $ setup_log $ key $ remote $ sni $ ip $ port)),
  Term.info "add"

let remove_cmd =
  Term.(term_result (const remove $ setup_log $ key $ remote $ sni)),
  Term.info "remove"

let help_cmd =
  let doc = "Tlstunnel configuration client" in
  Term.(ret (const help $ setup_log $ Term.man_format $ Term.choice_names $ Term.pure None)),
  Term.info "tlstunnel-client" ~doc

let cmds = [ help_cmd ; list_cmd ; add_cmd ; remove_cmd ]

let () = match Term.eval_choice help_cmd cmds with `Ok () -> exit 0 | _ -> exit 1
