
let ip =
  let f = function
    | `C1 i -> Ipaddr.(V4 (V4.of_int32 (Int32.of_int i)))
    | `C2 (a, b, c, d) ->
      let v6 =
        Int32.of_int a, Int32.of_int b, Int32.of_int c, Int32.of_int d
      in
      Ipaddr.(V6 (V6.of_int32 v6))
  and g = function
    | Ipaddr.V4 ip -> `C1 (Int32.to_int (Ipaddr.V4.to_int32 ip))
    | Ipaddr.V6 ip ->
      let a, b, c, d = Ipaddr.V6.to_int32 ip in
      `C2 (Int32.to_int a, Int32.to_int b, Int32.to_int c, Int32.to_int d)
  in
  Asn.S.(map f g (choice2
                    (explicit 0 int)
                    (explicit 1 (sequence4 (required int) (required int)
                                   (required int) (required int)))))

let sni =
  let f (sni, host, port) =
    Domain_name.(host_exn (of_string_exn sni)), host, port
  and g (sni, host, port) =
    Domain_name.to_string sni, host, port
  in
  Asn.S.(map f g
           (sequence3
              (required ~label:"sni" utf8_string)
              (required ~label:"host" ip)
              (required ~label:"port" int)))

let data =
  let f = function
    | `C1 s -> s
    | `C2 () -> assert false
  and g s = `C1 s
  in
  Asn.S.(map f g (choice2 (sequence_of sni) (explicit 1 null)))

let decode_strict codec cs =
  match Asn.decode codec cs with
  | Ok (a, rest) ->
    if String.length rest = 0 then
      Ok a
    else
      Error (`Msg "trailing bytes")
  | Error (`Parse msg) -> Error (`Msg msg)

let projections_of asn =
  let c = Asn.codec Asn.der asn in
  (decode_strict c, Asn.encode c)

let data_of_cs, data_to_cs = projections_of data

let decode_data data =
  match data_of_cs data with
  | Ok snis ->
    List.fold_left
      (fun acc (sni, host, port) ->
         match Domain_name.Host_map.mem sni acc with 
         | true -> 
          let entry = Option.fold ~none:[] ~some:(fun x -> x)
          (Domain_name.Host_map.find_opt sni acc) in 
          let ips = (host,port) :: entry in 
          Domain_name.Host_map.add sni ips acc
         | false -> Domain_name.Host_map.add sni [(host, port)] acc)
      Domain_name.Host_map.empty snis
  | Error `Msg msg ->
    Logs.err (fun m -> m "error %s decoding data" msg);
    assert false

let encode_data sni =
  let snis =
    Domain_name.Host_map.fold
      (fun sni addresses acc -> 
        List.map (fun (ip, port) -> (sni, ip, port)) addresses @ acc)
      sni []
  in
  data_to_cs snis

let add_sni snis (sni, host, port) =
  match Domain_name.Host_map.find_opt sni snis with
   | None -> 
    Domain_name.Host_map.add sni [(host, port)] snis
   | Some entries ->
     Logs.info (fun m -> m "adding new ip for %a %a:%d"
                   Domain_name.pp sni Ipaddr.pp host port);
     Domain_name.Host_map.add sni ((host, port) :: entries) snis

let remove_sni snis sni =
  Logs.info (fun m -> m "%a is no longer redirected" Domain_name.pp sni);
  Domain_name.Host_map.remove sni snis

let remove_ip_from_sni snis (sni, host, port) =
  Logs.info (fun m -> m "%a is no longer redirected" Domain_name.pp sni);
  match Domain_name.Host_map.find_opt sni snis with
  | None -> snis
  | Some entries ->
    let new_entries = List.filter (fun (h, p) -> h <> host || p <> port) entries in
    if new_entries = [] then
      Domain_name.Host_map.remove sni snis
    else
      Domain_name.Host_map.add sni new_entries snis

type cmd =
  | Add of [`host] Domain_name.t * Ipaddr.t * int
  | Remove_all of [`host] Domain_name.t
  | Remove of [`host] Domain_name.t * Ipaddr.t * int
  | List
  | Snis of ([`host] Domain_name.t * Ipaddr.t * int) list
  | Result of int * string

let pp_one ppf (sni, host, port) =
    Fmt.pf ppf "%a -> %a:%u" Domain_name.pp sni Ipaddr.pp host port

let pp_cmd ppf = function
  | Add (s, h, p) -> Fmt.pf ppf "adding %a" pp_one (s, h, p)
  | Remove_all sni -> Fmt.pf ppf "removing the domain %a" Domain_name.pp sni
  | Remove (sni, h, p) -> Fmt.pf ppf "removing the ip from %a" pp_one (sni, h, p)
  | List -> Fmt.string ppf "list"
  | Snis xs -> Fmt.(list ~sep:(any ";@ ") pp_one) ppf xs
  | Result (c, msg) -> Fmt.pf ppf "exited %d: %s" c msg

let cmd =
  let f = function
    | `C1 (s, h, p) -> Add (s, h, p)
    | `C2 s -> Remove_all Domain_name.(host_exn (of_string_exn s))
    | `C3 (s, h, p) -> Remove (s, h, p)
    | `C4 () -> List
    | `C5 xs -> Snis xs
    | `C6 (c, s) -> Result (c, s)
  and g = function
    | Add (s, h, p) -> `C1 (s, h, p)
    | Remove_all s -> `C2 (Domain_name.to_string s)
    | Remove (s, h, p) -> `C3 (s, h, p)
    | List -> `C4 ()
    | Snis xs -> `C5 xs
    | Result (c, s) -> `C6 (c, s)
  in
  Asn.S.(map f g
           (choice6
              (explicit 0 sni)
              (explicit 1 utf8_string)
              (explicit 2 sni)
              (explicit 3 null)
              (explicit 4 (sequence_of sni))
              (explicit 5 (sequence2
                             (required ~label:"exit" int)
                             (required ~label:"message" utf8_string)))))

let cmd_of_str, cmd_to_str = projections_of cmd
