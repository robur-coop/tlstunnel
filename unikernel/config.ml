(* mirage >= 4.4.1 & < 4.5.0 *)
(* (c) 2019 Hannes Mehnert, all rights reserved *)

open Mirage

let frontend_port =
  let doc = Key.Arg.info ~doc:"The TCP port of the frontend." ["frontend-port"] in
  Key.(create "frontend_port" Arg.(opt int 443 doc))

let key =
  let doc = Key.Arg.info ~doc:"The shared secret" ["key"] in
  Key.(create "key" Arg.(required string doc))

let configuration_port =
  let doc = Key.Arg.info ~doc:"The TCP port for configuration." ["configuration-port"] in
  Key.(create "configuration_port" Arg.(opt int 1234 doc))

let certs_key = Key.(value @@ kv_ro ~group:"certs" ())
let certs = generic_kv_ro ~key:certs_key "tls"

let main =
  foreign
    ~keys:[ Key.v frontend_port ;
            Key.v key ;
            Key.v configuration_port ;
          ]
    ~packages:[
      package ~min:"0.14.0" "tls-mirage" ;
      package ~min:"6.0.0" "cstruct" ;
      package ~min:"7.0.0" "tcpip" ;
      package "metrics";
    ]
    "Unikernel.Main"
    (random @-> time @-> pclock @-> block @-> stackv4v6 @-> stackv4v6 @-> kv_ro @-> job)

(* uTCP *)

let tcpv4v6_direct_conf id =
  let packages_v = Key.pure [ package "utcp" ~sublibs:[ "mirage" ] ] in
  let connect _ modname = function
    | [_random; _mclock; _time; ip] ->
      Fmt.str "Lwt.return (%s.connect %S %s)" modname id ip
    | _ -> failwith "direct tcpv4v6"
  in
  impl ~packages_v ~connect "Utcp_mirage.Make"
    (random @-> mclock @-> time @-> ipv4v6 @-> (tcp: 'a tcp typ))

let direct_tcpv4v6
    ?(clock=default_monotonic_clock)
    ?(random=default_random)
    ?(time=default_time) id ip =
  tcpv4v6_direct_conf id $ random $ clock $ time $ ip

let net ?group name netif =
  let ethernet = etif netif in
  let arp = arp ethernet in
  let i4 = create_ipv4 ?group ethernet arp in
  let i6 = create_ipv6 ?group netif ethernet in
  let i4i6 = create_ipv4v6 ?group i4 i6 in
  let tcpv4v6 = direct_tcpv4v6 name i4i6 in
  let ipv4_only = Key.ipv4_only ?group () in
  let ipv6_only = Key.ipv6_only ?group () in
  direct_stackv4v6 ~tcp:tcpv4v6 ~ipv4_only ~ipv6_only netif ethernet arp i4 i6

let use_utcp =
  let doc = Key.Arg.info ~doc:"Use uTCP" [ "use-utcp" ] in
  Key.(create "use-utcp" Arg.(flag ~stage:`Configure doc))

let stack =
  if_impl
    (Key.value use_utcp)
    (net "service" default_network)
    (generic_stackv4v6 default_network)

let private_stack =
  if_impl
    (Key.value use_utcp)
    (net ~group:"private" "private" (netif ~group:"private" "private"))
    (generic_stackv4v6 ~group:"private" (netif ~group:"private" "private"))

let block =
  Key.(if_impl is_solo5 (block_of_file "storage") (block_of_file "disk.img"))

let enable_monitoring =
  let doc = Key.Arg.info
      ~doc:"Enable monitoring (only available for solo5 targets)"
      [ "enable-monitoring" ]
  in
  Key.(create "enable-monitoring" Arg.(flag ~stage:`Configure doc))

let management_stack =
  if_impl
    (Key.value enable_monitoring)
    (if_impl
       (Key.value use_utcp)
       (net ~group:"management" "management" (netif ~group:"management" "management"))
       (generic_stackv4v6 ~group:"management" (netif ~group:"management" "management")))
    stack

let name =
  let doc = Key.Arg.info ~doc:"Name of the unikernel" [ "name" ] in
  Key.(v (create "name" Arg.(opt string "roburtls" doc)))

let monitoring =
  let monitor =
    let doc = Key.Arg.info ~doc:"monitor host IP" ["monitor"] in
    Key.(v (create "monitor" Arg.(opt (some ip_address) None doc)))
  in
  let connect _ modname = function
    | [ _ ; _ ; stack ] ->
      Fmt.str "Lwt.return (match %a with\
               | None -> Logs.warn (fun m -> m \"no monitor specified, not outputting statistics\")\
               | Some ip -> %s.create ip ~hostname:%a %s)"
        Key.serialize_call monitor modname
        Key.serialize_call name stack
    | _ -> assert false
  in
  impl
    ~packages:[ package "mirage-monitoring" ]
    ~keys:[ name ; monitor ]
    ~connect "Mirage_monitoring.Make"
    (time @-> pclock @-> stackv4v6 @-> job)

let syslog =
  let syslog =
    let doc = Key.Arg.info ~doc:"syslog host IP" ["syslog"] in
    Key.(v (create "syslog" Arg.(opt (some ip_address) None doc)))
  in
  let connect _ modname = function
    | [ _ ; stack ] ->
      Fmt.str "Lwt.return (match %a with\
               | None -> Logs.warn (fun m -> m \"no syslog specified, dumping on stdout\")\
               | Some ip -> Logs.set_reporter (%s.create %s ip ~hostname:%a ()))"
        Key.serialize_call syslog modname stack
        Key.serialize_call name
    | _ -> assert false
  in
  impl
    ~packages:[ package ~sublibs:["mirage"] ~min:"0.4.0" "logs-syslog" ]
    ~keys:[ name ; syslog ]
    ~connect "Logs_syslog_mirage.Udp"
    (pclock @-> stackv4v6 @-> job)


type i0 = I0
let i0 = Functoria.Type.v I0
let no0 = Functoria.impl "Int" job

type n1 = N1
let n1 = Functoria.Type.v N1
let noop1 = Functoria.impl "Set.Make" (job @-> job)

let optional_monitoring time pclock stack =
  if_impl (Key.value enable_monitoring)
    (monitoring $ time $ pclock $ stack)
    (noop1 $ no0)

let optional_syslog pclock stack =
  if_impl (Key.value enable_monitoring)
    (syslog $ pclock $ stack)
    (noop1 $ no0)

let () =
  register "tlstunnel"
    [
      optional_syslog default_posix_clock management_stack ;
      optional_monitoring default_time default_posix_clock management_stack ;
      main $ default_random $ default_time $ default_posix_clock $ block $ stack $ private_stack $ certs
    ]
