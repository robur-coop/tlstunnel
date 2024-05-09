(* mirage >= 4.5.0 & < 4.6.0 *)
(* (c) 2019 Hannes Mehnert, all rights reserved *)

open Mirage

let setup = runtime_key ~pos:__POS__ "Unikernel.K.setup"

let main =
  main
    ~runtime_keys:[setup]
    ~packages:[
      package ~min:"0.14.0" "tls-mirage" ;
      package ~min:"5.0.1" ~sublibs:["mirage"] "dns-certify" ;
      package ~min:"6.0.0" "cstruct" ;
      package ~min:"7.0.0" "tcpip" ;
      package "metrics";
      package ~min:"4.5.0" ~sublibs:["network"] "mirage-runtime";
    ]
    "Unikernel.Main"
    (random @-> time @-> pclock @-> block @-> stackv4v6 @-> stackv4v6 @-> job)

(* uTCP *)

let tcpv4v6_direct_conf id =
  let packages_v = Key.pure [ package "utcp" ~sublibs:[ "mirage" ] ] in
  let connect _ modname = function
    | [_random; _mclock; _time; ip] ->
      code ~pos:__POS__ "Lwt.return (%s.connect %S %s)" modname id ip
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
  let ipv4_only = Runtime_arg.ipv4_only ?group () in
  let ipv6_only = Runtime_arg.ipv6_only ?group () in
  direct_stackv4v6 ~tcp:tcpv4v6 ~ipv4_only ~ipv6_only netif ethernet arp i4 i6

let use_utcp =
  let doc = Key.Arg.info ~doc:"Use uTCP" [ "use-utcp" ] in
  Key.(create "use-utcp" Arg.(flag doc))

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
  Key.(create "enable-monitoring" Arg.(flag doc))

let management_stack =
  if_impl
    (Key.value enable_monitoring)
    (if_impl
       (Key.value use_utcp)
       (net ~group:"management" "management" (netif ~group:"management" "management"))
       (generic_stackv4v6 ~group:"management" (netif ~group:"management" "management")))
    stack

let docs = "MONITORING PARAMETERS"

let name =
  runtime_arg ~pos:__POS__ ~name:"name"
    {|(let doc = Cmdliner.Arg.info ~doc:"Name of the unikernel" ~docs:%S [ "name" ] in
       Cmdliner.Arg.(value & opt string "a.ns.robur.coop" doc))|} docs

let monitoring =
  let monitor = Runtime_arg.(v (monitor ~docs None)) in
  let connect _ modname = function
    | [ _ ; _ ; stack ; name ; monitor ] ->
      code ~pos:__POS__
        "Lwt.return (match %s with\
         | None -> Logs.warn (fun m -> m \"no monitor specified, not outputting statistics\")\
         | Some ip -> %s.create ip ~hostname:%s %s)"
        monitor modname name stack
    | _ -> assert false
  in
  impl
    ~packages:[ package "mirage-monitoring" ]
    ~runtime_args:[ name ; monitor ]
    ~connect "Mirage_monitoring.Make"
    (time @-> pclock @-> stackv4v6 @-> job)

let syslog =
  let syslog = Runtime_arg.(v (syslog ~docs None)) in
  let connect _ modname = function
    | [ _ ; stack ; name ; syslog ] ->
      code ~pos:__POS__
        "Lwt.return (match %s with\
         | None -> Logs.warn (fun m -> m \"no syslog specified, dumping on stdout\")\
         | Some ip -> Logs.set_reporter (%s.create %s ip ~hostname:%s ()))"
        syslog modname stack name
    | _ -> assert false
  in
  impl
    ~packages:[ package ~sublibs:["mirage"] ~min:"0.4.0" "logs-syslog" ]
    ~runtime_args:[ name ; syslog ]
    ~connect "Logs_syslog_mirage.Udp"
    (pclock @-> stackv4v6 @-> job)

let optional_monitoring time pclock stack =
  if_impl (Key.value enable_monitoring)
    (monitoring $ time $ pclock $ stack)
    noop

let optional_syslog pclock stack =
  if_impl (Key.value enable_monitoring)
    (syslog $ pclock $ stack)
    noop

let () =
  register "tlstunnel"
    [
      optional_syslog default_posix_clock management_stack ;
      optional_monitoring default_time default_posix_clock management_stack ;
      main $ default_random $ default_time $ default_posix_clock $ block $ stack $ private_stack
    ]
