(require
  hiolib.rule :readers * *)

(import
  sys
  json
  time [sleep time]
  math [modf]
  random [getrandbits choice]
  functools [cached-property partial]
  collections [deque]
  enum [IntEnum]
  logging
  logging [getLogger]
  threading [Thread]
  socket
  scapy.all :as sp
  pcap :as pypcap
  hiolib.rule *
  hpacket.pcap *
  hpacket.inet *)

(defclass IPVer [IntEnum]
  (setv V4 4 V6 6))

(defclass IPCtx []
  (setv ipver None)

  (defn [cached-property] IP [self]
    (ecase self.ipver
           IPVer.V4 IPv4
           IPVer.V6 IPv6))

  (defn [cached-property] IPError [self]
    (ecase self.ipver
           IPVer.V4 IPv4Error
           IPVer.V6 IPv6Error))

  (defn [cached-property] ICMP [self]
    (ecase self.ipver
           IPVer.V4 ICMPv4
           IPVer.V6 ICMPv6))

  (defn [cached-property] ICMPEchoReq [self]
    (ecase self.ipver
           IPVer.V4 ICMPv4EchoReq
           IPVer.V6 ICMPv6EchoReq))

  (defn [cached-property] ICMPEchoRep [self]
    (ecase self.ipver
           IPVer.V4 ICMPv4EchoRep
           IPVer.V6 ICMPv6EchoRep))

  (defn [cached-property] ICMPDestUnreach [self]
    (ecase self.ipver
           IPVer.V4 ICMPv4DestUnreach
           IPVer.V6 ICMPv6DestUnreach))

  (defn [cached-property] ICMPParamProblem [self]
    (ecase self.ipver
           IPVer.V4 ICMPv4ParamProblem
           IPVer.V6 ICMPv6ParamProblem)))



(defn sp-get-iface [iface]
  (when (and (= sys.platform "win32") (!= iface "\\Device\\NPF_Loopback"))
    (setv iface (.removeprefix iface "\\Device\\NPF_")))
  (get sp.conf.ifaces iface))

;; NOTICE: CHANGE GLOBAL STATE!!!
(defn sp-set-iface [iface]
  (setv sp.conf.iface (sp-get-iface iface)))

(defn guess-iface-by-ip [sp-route ip]
  (get (.route sp-route ip) 0))

(setv guess-iface-by-ipv4 (partial guess-iface-by-ip sp.conf.route)
      guess-iface-by-ipv6 (partial guess-iface-by-ip sp.conf.route6))

(defn get-route-by-ip [sp-route ip]
  (let [route (.route sp-route ip)]
    (when (!= (sp-get-iface (get route 0)) sp.conf.iface)
      (raise RuntimeError))
    route))

(setv get-route-by-ipv4 (partial get-route-by-ip sp.conf.route)
      get-route-by-ipv6 (partial get-route-by-ip sp.conf.route6))

(setv get-mac-by-ipv4 sp.getmacbyip
      get-mac-by-ipv6 sp.getmacbyip6)

(defn get-default-mac []
  sp.conf.iface.mac)



(defclass TargetCtx [IPCtx]
  (setv ipver None)

  (defn #-- init [self [iface None] [dst None] [src None] [next-hop None] [mac-dst None] [mac-src None]]
    ;; - iface: The iface is usually determined by the dst, but
    ;; considering that the link-local address may lead to ambiguity,
    ;; it is necessary to manually specify it even when the routing
    ;; table is reliable.
    ;;
    ;; - route: The src and next-hop are usually determined by the dst
    ;; and iface. It is important to note that the src does not affect
    ;; the selection of the iface. Therefore, if the dst is a
    ;; link-local address on the link of the iface A, then iface
    ;; should be specified as iface A instead of specifying the src as
    ;; the link-local address of iface A.
    ;;
    ;; - mac: the mac-dst and mac-src are usually determined by the
    ;; next-hop and iface. It is important to note that root
    ;; privileges are required to reslove the mac-dst.

    (unless dst
      (raise ValueError))

    (setv self.iface (or iface (self.get-default-iface dst)))

    ;; NOTICE: CHANGE GLOBAL STATE!!!
    (sp-set-iface self.iface)

    (setv self.dst      dst
          self.src      (or src (get self.default-route 1))
          self.next-hop (or next-hop (get self.default-route 2))
          self.mac-dst  (or mac-dst self.default-mac-dst)
          self.mac-src  (or mac-src self.default-mac-src)))

  (defn get-default-iface [self dst]
    ((ecase self.ipver
            IPVer.V4 guess-iface-by-ipv4
            IPVer.V6 guess-iface-by-ipv6)
      dst))

  (defn [property] default-route [self]
    ((ecase self.ipver
            IPVer.V4 get-route-by-ipv4
            IPVer.V6 get-route-by-ipv6)
      self.dst))

  (defn [property] default-mac-dst [self]
    (ecase self.ipver
           IPVer.V4 (get-mac-by-ipv4 (if (= self.next-hop "0.0.0.0") self.dst self.next-hop))
           IPVer.V6 (get-mac-by-ipv6 (if (= self.next-hop "::"     ) self.dst self.next-hop))))

  (defn [property] default-mac-src [self]
    (get-default-mac))

  (defn get-info [self]
    (dfor attr #("iface" "dst" "src" "next-hop" "mac-dst" "mac-src")
          attr (getattr self (hy.mangle attr))))

  (defn [classmethod] get-args-spec [cls]
    [["-i" "--iface"]
     ["-d" "--dst"]
     ["-s" "--src"]
     ["-n" "--next-hop"]
     ["-D" "--mac-dst"]
     ["-S" "--mac-src"]])

  (defn [classmethod] get-kwargs-from-args [cls args]
    (dfor attr #("iface" "dst" "src" "next-hop" "mac-dst" "mac-src")
          (hy.mangle attr) (getattr args (hy.mangle attr)))))

(defclass TargetPortCtxMixin []
  (defn #-- init [self [port 53] #** kwargs]
    (#super-- init #** kwargs)
    (setv self.port port))

  (defn get-info [self]
    {#** (#super get-info) "port" self.port})

  (defn [classmethod] get-args-spec [cls]
    [#* (#super get-args-spec)
     ["-P" "--port" :type int :default 53]])

  (defn [classmethod] get-kwargs-from-args [cls args]
    {#** (#super get-kwargs-from-args args)
     "port" args.port}))

(defclass TargetDNSNameMixin []
  (defn #-- init [self [dst None] #** kwargs]
    (setv self.dnsname dst)
    (let [addr-info (choice (socket.getaddrinfo dst 0))
          addr-family (get addr-info 0)
          addr (get addr-info -1 0)]
      (setv self.ipver (ecase addr-family
                              socket.AF-INET  IPVer.V4
                              socket.AF-INET6 IPVer.V6))
      (#super-- init :dst addr #** kwargs)))

  (defn get-info [self]
    {#** (#super get-info) "dnsname" self.dnsname}))



(defclass SendRecvCtx [TargetCtx]
  (defn [property] pcap-filter [self]
    (.format (ecase self.ipver
                    IPVer.V4 "ip src {}"
                    IPVer.V6 "ip6 src {}")
             self.dst))

  (defn get-pcap [self]
    (doto (pypcap.pcap :name self.iface :promisc False :timeout-ms 100)
          (.setdirection pypcap.PCAP-D-IN)
          (.setfilter self.pcap-filter)
          (.setnonblock)))

  (defn prepare [self]
    (setv self.pcap (.get-pcap self)
          self.packets (list)))

  (defn cleanup [self]
    (.close self.pcap)
    (.sort self.packets :key (fn [x] (get x 0))))

  (defn send-packet [self packet]
    (.append self.packets #((time) packet))
    (.sendpacket self.pcap packet))

  (defn recv-packets [self]
    (let [packets (list (.readpkts self.pcap))]
      (+= self.packets packets)
      (lfor #(ts packet) packets packet))))



(defclass FPCtx [SendRecvCtx]
  (setv logger None
        fp-classes None)

  (defn [classmethod] register [cls fp-class]
    (.append cls.fp-classes fp-class)
    fp-class)

  (defn #-- init-subclass [cls #* args #** kwargs]
    (#super-- init-subclass #* args #** kwargs)
    (setv cls.logger (getLogger (. cls #-- class #-- name))))

  (defn #-- init [self [send-attempts 2] [send-interval 0.01] [send-timewait 0.2] [output-path "neofp"] #** kwargs]
    ;; The id and seq (both 8 bits) are embedded in:
    ;;
    ;; - ipv6 flow label, extract from ipv6 error in icmpv6 error messages
    ;; - icmpv6 echo request id and seq, extract from icmpv6 echo reply id and seq
    ;; - tcp src port, extract from tcp dst port
    ;;
    ;; tcp note: cannot count on seq/ack embedded id and seq, because
    ;; probe may not be syn, and even response may not be ack

    (#super-- init #** kwargs)

    (setv self.id (+ 0x80 (getrandbits 7)))

    (setv self.send-attempts send-attempts
          self.send-interval send-interval
          self.send-timewait send-timewait
          self.output-path   output-path)

    (setv self.fps (lfor #(seq fp-class) (enumerate self.fp-classes) (fp-class :ctx self :seq seq))))

  (defn get-answer-idseq [self parsed-answer]
    ;; return #(id seq) if it is a valid answer
    (raise NotImplementedError))

  (defn prepare [self]
    (#super prepare)
    (for [fp self.fps]
      (.prepare fp))
    (setv self.send-finished False
          self.recv-queue (deque)))

  (defn dispatch-answers [self]
    (while self.recv-queue
      (let [answer (.popleft self.recv-queue)
            parsed-answer (Ether.parse answer)
            idseq (.get-answer-idseq self parsed-answer)]
        (when idseq
          (let [#(id seq) idseq]
            (when (and (= id self.id) (chainc 0 <= seq < (len self.fps)))
              (let [fp (get self.fps seq)]
                (.append fp.answers answer)
                (.append fp.parsed-answers parsed-answer))))))))

  (defn sender [self]
    (for [i (range self.send-attempts)]
      (for [#(seq fp) (enumerate self.fps)]
        (unless fp.answers
          (.info self.logger "[send] turn=%d, seq=%d, name=%s" i seq (. fp #-- class #-- name))
          (for [probe fp.probes]
            (.send-packet self probe)
            (sleep self.send-interval))))
      (sleep self.send-timewait)
      (.dispatch-answers self)
      (let [count (cfor sum fp self.fps (not fp.answers))]
        (.info self.logger "[send] turn=%d, unanswered=%d/%d" i count (len self.fps))
        (when (= count 0)
          (break)))))

  (defn recver [self]
    (while (not self.send-finished)
      (for [answer (.recv-packets self)]
        (.append self.recv-queue answer))
      (sleep 0.001)))

  (defn run [self]
    (.prepare self)
    (let [recver (Thread :target self.recver)]
      (.start recver)
      (try
        (.sender self)
        (except [e Exception]
          (.info self.logger "[send]: except while sending %s" e))
        (finally
          (setv self.send-finished True)
          (.join recver))))
    (.cleanup self))

  (defn get-fp-feat [self fp]
    ;; return a dict of #(name value) or None
    (raise NotImplementedError))

  (defn [classmethod] get-fp-feat-names [cls fp-class]
    ;; return a list of names
    (raise NotImplementedError))

  (defn get-feat [self]
    (let [feat (dict)]
      (for [fp self.fps]
        (for [#(k v) (.items (or (.get-fp-feat self fp) (dict)))]
          (setv (get feat (.format "{}.{}" (. fp #-- class #-- name) k)) v)))
      feat))

  (defn [classmethod] get-feat-names [cls]
    (let [names (list)]
      (for [fp-class cls.fp-classes]
        (for [k (.get-fp-feat-names cls fp-class)]
          (.append names (.format "{}.{}" (. fp-class #-- name) k))))
      names))

  (defn get-info [self]
    {"id" self.id #** (#super get-info)})

  (defn [property] output-info-json-path [self]
    (.format "{}.info.json" self.output-path))

  (defn [property] output-all-pcap-path [self]
    (.format "{}.all.pcap" self.output-path))

  (defn [property] output-pcap-path [self]
    (.format "{}.pcap" self.output-path))

  (defn [property] output-json-path [self]
    (.format "{}.json" self.output-path))

  (defn output-info-json [self]
    (with [f (open self.output-info-json-path "w")]
      (json.dump (.get-info self) f)))

  (defn output-all-pcap [self]
    (with [f (open self.output-all-pcap-path "wb")]
      (let [writer (Pcap.writer f)]
        (for [#(ts packet) self.packets]
          (let [#(msec sec) (modf ts)]
            (.write-packet writer packet :sec (int sec) :msec (int (* msec 1,000,000))))))))

  (defn output-pcap [self]
    (with [f (open self.output-pcap-path "wb")]
      (let [writer (Pcap.writer f)]
        (for [#(seq fp) (enumerate self.fps)]
          (.write-parsed-packet writer (/ (Ether) (.encode (. fp #-- class #-- name))) :sec seq :msec 0)
          (for [probe fp.probes]
            (.write-packet writer probe :sec seq :msec 1))
          (for [answer fp.answers]
            (.write-packet writer answer :sec seq :msec 2))))))

  (defn output-json [self]
    (with [f (open self.output-json-path "w")]
      (json.dump (.get-feat self) f)))

  (defn output [self]
    (.output-info-json self)
    (.output-all-pcap self)
    (.output-pcap self)
    (.output-json self))

  (defn log-info [self]
    (for [#(k v) (.items (.get-info self))]
      (.info self.logger "[info] %s=%s" k v)))

  (defn log-fps [self]
    (for [#(seq fp) (enumerate self.fps)]
      (.info self.logger "[fp] seq=%d, name=%s" seq (. fp #-- class #-- name))))

  (defn [classmethod] get-args-spec [cls]
    [#* (#super get-args-spec)
     ["-A" "--send-attempts" :type int :default 2]
     ["-I" "--send-interval" :type float :default 0.01]
     ["-T" "--send-timewait" :type float :default 0.2]
     ["-o" "--output-path" :default "noefp"]
     ["-l" "--list" :action "store_true" :default False]])

  (defn [classmethod] get-kwargs-from-args [cls args]
    {#** (#super get-kwargs-from-args args)
     #** (dfor attr #("send-attempts" "send-interval" "send-timewait" "output-path")
               (hy.mangle attr) (getattr args (hy.mangle attr)))})

  (defn [classmethod] log-config [cls]
    (logging.basicConfig
      :level   "INFO"
      :format  "%(asctime)s %(name)s %(levelname)s %(message)s"
      :datefmt "%H:%M:%S"))

  (defn [classmethod] main [cls]
    (.log-config cls)
    (let [args (parse-args (.get-args-spec cls))]
      (let [ctx (cls #** (.get-kwargs-from-args cls args))]
        (.log-info ctx)
        (if args.list
            (.log-fps ctx)
            (do
              (.run ctx)
              (.output ctx)))))))



(defn idseq-packB [id seq]
  (+ (<< id 8) seq))

(defn idseq-unpackB [x]
  #((>> x 8) (& x 0xff)))

(defn idseq-packH [id seq]
  (+ (<< id 16) seq))

(defn idseq-unpackH [x]
  #((>> x 16) (& x 0xffff)))

(defclass FP []
  (defn #-- init [self ctx seq]
    (setv self.ctx ctx
          self.seq seq))

  (defn [cached-property] idseqB [self]
    (idseq-packB self.ctx.id self.seq))

  (defn [cached-property] idseqH [self]
    (idseq-packH self.ctx.id self.seq))

  (defn prepare [self]
    (setv self.parsed-probes  (.make-probes self)
          self.probes         (lfor probe self.parsed-probes (.build probe))
          self.parsed-answers (list)
          self.answers        (list)))

  (defn make-probe [self]
    (raise NotImplementedError))

  (defn make-probes [self]
    [(.make-probe self)])

  (defn make-ipv4 [self #** kwargs]
    (IPv4 :id self.idseqB :src self.ctx.src :dst self.ctx.dst #** kwargs))

  (defn make-ipv6 [self #** kwargs]
    (IPv6 :fl self.idseqB :src self.ctx.src :dst self.ctx.dst #** kwargs))

  (defn make-ip [self #** kwargs]
    (ecase self.ctx.ipver
           IPVer.V4 (.make-ipv4 self #** kwargs)
           IPVer.V6 (.make-ipv6 self #** kwargs)))

  (defn make-ip-with-ether [self #** kwargs]
    (/ (Ether :src self.ctx.mac-src :dst self.ctx.mac-dst)
       (.make-ip self #** kwargs)))

  (defn make-pingv4 [self [code 0] [data (bytes 32)]]
    (/ (ICMPv4 :type ICMPv4Type.EchoReq :code code)
       (ICMPv4EchoReq :id self.ctx.id :seq self.seq)
       data))

  (defn make-pingv6 [self [code 0] [data (bytes 32)]]
    (/ (ICMPv6 :type ICMPv6Type.EchoReq :code code)
       (ICMPv6EchoReq :id self.ctx.id :seq self.seq)
       data))

  (defn make-ping [self [code 0] [data (bytes 32)]]
    (ecase self.ctx.ipver
           IPVer.V4 (.make-pingv4 self code data)
           IPVer.V6 (.make-pingv6 self code data)))

  (defn build-pload [self pload #** kwargs]
    (let [packet (/ (.make-ip self #** kwargs) pload)]
      (.build packet)
      packet.pload))

  (defn build-ping [self [code 0] [data (bytes 32)] #** kwargs]
    (.build-pload self (.make-ping self code data) #** kwargs))

  (defn make-udp-with-rand-port [self]
    (UDP :src self.idseqB :dst self.idseqB))

  (defn make-tcp-with-rand-port [self #** kwargs]
    (TCP :src self.idseqB :dst self.idseqB :seq self.idseqH #** kwargs))

  (defn make-tcp-with-target-port [self #** kwargs]
    (TCP :src self.idseqB :dst self.ctx.port :seq self.idseqH #** kwargs)))



(defclass BaseICMPFPCtx [FPCtx]
  (defn get-answer-idseq [self parsed-answer]
    (let [head (get parsed-answer self.ICMP)]
      (when head
        (setv head head.next-packet)
        (cond (isinstance head self.ICMPEchoRep)
              #(head.id head.seq)
              (isinstance head #(self.ICMPDestUnreach self.ICMPParamProblem))
              (do
                (setv head head.next-packet)
                (when (isinstance head self.IPError)
                  (idseq-unpackB (ecase self.ipver
                                        IPVer.V4 head.id
                                        IPVer.V6 head.fl))))))))

  (defn get-ip-feat [self ip]
    (dfor k (.get-ip-feat-names self)
          k (getattr ip k)))

  (defn [classmethod] get-ip-feat-names [cls]
    (ecase cls.ipver
           IPVer.V4 ["ihl" "tos" "tlen" "id" "DF" "proto"]
           IPVer.V6 ["tc" "fl" "nh" "plen"]))

  (defn get-fp-feat [self fp]
    (when fp.parsed-answers
      (let [parsed-answer (get fp.parsed-answers 0)
            ip (get parsed-answer self.IP)
            icmp (get ip self.ICMP)
            np icmp.next-packet]
        {#** (.get-ip-feat self ip)
         "type" icmp.type
         "code" icmp.code
         "args" (cond (isinstance np self.ICMPDestUnreach)
                      np.unused
                      (isinstance np self.ICMPParamProblem)
                      np.ptr
                      True
                      0)})))

  (defn [classmethod] get-fp-feat-names [cls fp-class]
    [#* (.get-ip-feat-names cls) "type" "code" "args"]))



(defclass BaseTCPFPCtx [TargetDNSNameMixin TargetPortCtxMixin FPCtx]
  (defn get-answer-idseq [self parsed-answer]
    (let [head (get parsed-answer self.IP)]
      (when head
        (setv head head.next-packet)
        (when (isinstance head TCP)
          (idseq-unpackB head.dst)))))

  (defn get-fp-feat [self fp]
    (when fp.parsed-answers
      (let [parsed-answer (get fp.parsed-answers 0)
            head (get parsed-answer TCP)
            feat (dfor attr #("seq" "ack" "dataofs" "res" "C" "E" "U" "A" "P" "R" "S" "F" "win" "uptr")
                       attr (getattr head attr))]
        (for [i (range 8)]
          (if (< i (len head.opts))
              (let [#(type data) (get head.opts i)]
                (setv (get feat (.format "opttype{}" i)) type
                      (get feat (.format "optdata{}" i)) (if (isinstance data int) data (len (.pack TCPOpt type data)))))
              (setv (get feat (.format "opttype{}" i)) 0
                    (get feat (.format "optdata{}" i)) 0)))
        feat)))

  (defn [classmethod] get-fp-feat-names [cls fp-class]
    (let [names ["seq" "ack" "dataofs" "res" "C" "E" "U" "A" "P" "R" "S" "F" "win" "uptr"]]
      (for [i (range 8)]
        (.append names (.format "opttype{}" i))
        (.append names (.format "optdata{}" i)))
      names)))
