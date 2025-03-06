(* mirage >= 4.9.0 & < 4.10.0 *)
(* (c) 2019 Hannes Mehnert, all rights reserved *)

open Mirage

let main =
  main
    ~packages:[
      package ~min:"0.14.0" "tls-mirage" ;
      package ~min:"10.0.0" ~sublibs:["mirage"] "dns-certify" ;
      package ~min:"6.0.0" "cstruct" ;
      package ~min:"7.0.0" "tcpip" ;
      package "metrics";
      package ~min:"4.5.0" ~sublibs:["network"] "mirage-runtime";
    ]
    "Unikernel.Main"
    (block @-> stackv4v6 @-> stackv4v6 @-> job)

(* uTCP *)

let tcpv4v6_direct_conf id =
  let packages_v = Key.pure [ package "utcp" ~sublibs:[ "mirage" ] ] in
  let connect _ modname = function
    | [ip] ->
      code ~pos:__POS__ "Lwt.return (%s.connect %S %s)" modname id ip
    | _ -> failwith "direct tcpv4v6"
  in
  impl ~packages_v ~connect "Utcp_mirage.Make"
    (ipv4v6 @-> (tcp: 'a tcp typ))

let direct_tcpv4v6 id ip =
  tcpv4v6_direct_conf id $ ip

let net ?group name netif =
  let ethernet = ethif netif in
  let arp = arp ethernet in
  let i4 = create_ipv4 ?group ethernet arp in
  let i6 = create_ipv6 ?group netif ethernet in
  let i4i6 = create_ipv4v6 ?group i4 i6 in
  let tcpv4v6 = direct_tcpv4v6 name i4i6 in
  direct_stackv4v6 ?group ~tcp:tcpv4v6 netif ethernet arp i4 i6

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
      ~doc:"Enable monitoring (syslog, metrics to influx, log level, statmemprof tracing)"
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

let name =
  runtime_arg ~pos:__POS__
    {|let doc = Cmdliner.Arg.info ~doc:"Name of the unikernel"
        ~docs:Mirage_runtime.s_log [ "name" ]
      in
      Cmdliner.Arg.(value & opt string "a.ns.robur.coop" doc)|}

let monitoring =
  let monitor = Runtime_arg.(v (monitor None)) in
  let connect _ modname = function
    | [ stack ; name ; monitor ] ->
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
    (stackv4v6 @-> job)

let syslog =
  let syslog = Runtime_arg.(v (syslog None)) in
  let connect _ modname = function
    | [ stack ; name ; syslog ] ->
      code ~pos:__POS__
        "Lwt.return (match %s with\
         | None -> Logs.warn (fun m -> m \"no syslog specified, dumping on stdout\")\
         | Some ip -> Logs.set_reporter (%s.create %s ip ~hostname:%s ()))"
        syslog modname stack name
    | _ -> assert false
  in
  impl
    ~packages:[ package ~sublibs:["mirage"] ~min:"0.5.0" "logs-syslog" ]
    ~runtime_args:[ name ; syslog ]
    ~connect "Logs_syslog_mirage.Udp"
    (stackv4v6 @-> job)

let optional_monitoring stack =
  if_impl (Key.value enable_monitoring)
    (monitoring $ stack)
    noop

let optional_syslog stack =
  if_impl (Key.value enable_monitoring)
    (syslog $ stack)
    noop

let () =
  register "tlstunnel"
    [
      optional_syslog management_stack ;
      optional_monitoring management_stack ;
      main $ block $ stack $ private_stack
    ]
