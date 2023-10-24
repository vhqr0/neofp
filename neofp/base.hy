(require
  hiolib.rule :readers * *)

(import
  sys
  json
  time [sleep time]
  math [modf]
  random [getrandbits]
  functools [cached-property partial]
  collections [deque]
  logging
  logging [getLogger]
  threading [Thread]
  scapy.all :as sp
  pcap :as pypcap
  hiolib.rule *
  hpacket.pcap *
  hpacket.inet *)

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



(defn idseq-packB [id seq]
  (+ (<< id 8) seq))

(defn idseq-unpackB [x]
  #((>> x 8) (& x 0xff)))

(defn idseq-packH [id seq]
  (+ (<< id 16) seq))

(defn idseq-unpackH [x]
  #((>> x 16) (& x 0xffff)))



(defclass FPCtx []
  (setv logger None
        fp-classes None)

  (defn [classmethod] register [cls fp-class]
    (.append cls.fp-classes fp-class)
    fp-class)

  (defn #-- init-subclass [cls #* args #** kwargs]
    (#super-- init-subclass #* args #** kwargs)
    (setv cls.logger (getLogger (. cls #-- class #-- name))))

  (defn #-- init [self [iface None] [dst None] [src None] [next-hop None] [mac-dst None] [mac-src None]
                  [send-attempts 2] [send-interval 0.01] [send-timewait 0.2] [output-path "neofp"]]
    ;; - id: The id and seq (bots 8 bits) are embedded in the flow
    ;; label of ipv6 and the id and seq of icmpv6 echo request to
    ;; ensure that it can distinguish whether an icmpv6 error message
    ;; or echo reply comes from the process and the corresponding
    ;; probe group.
    ;;
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

    (setv self.id    (+ 0x80 (getrandbits 7))
          self.iface (or iface (self.get-default-iface dst)))

    ;; NOTICE: CHANGE GLOBAL STATE!!!
    (sp-set-iface self.iface)

    (setv self.dst           dst
          self.src           (or src (get self.default-route 1))
          self.next-hop      (or next-hop (get self.default-route 2))
          self.mac-dst       (or mac-dst self.default-mac-dst)
          self.mac-src       (or mac-src self.default-mac-src)
          self.send-attempts send-attempts
          self.send-interval send-interval
          self.send-timewait send-timewait
          self.output-path   output-path
          self.fps           (lfor #(seq fp-class) (enumerate self.fp-classes) (fp-class :ctx self :seq seq))))

  (defn get-default-iface [self dst]
    (raise NotImplementedError))

  (defn [property] default-route [self]
    (raise NotImplementedError))

  (defn [property] default-mac-dst [self]
    (raise NotImplementedError))

  (defn [property] default-mac-src [self]
    (get-default-mac))

  (defn [property] pcap-filter [self]
    (raise NotImplementedError))

  (defn [property] output-pcap-path [self]
    (.format "{}.pcap" self.output-path))

  (defn [property] output-all-pcap-path [self]
    (.format "{}.all.pcap" self.output-path))

  (defn [property] output-json-path [self]
    (.format "{}.json" self.output-path))

  (defn log-info [self]
    (for [attr #("id" "iface" "dst" "src" "next-hop" "mac-dst" "mac-src")]
      (.info self.logger "[attr] %s=%s" attr (getattr self (hy.mangle attr))))
    (for [#(seq fp) (enumerate self.fps)]
      (.info self.logger "[fp] seq=%d, namd=%s" seq (. fp #-- class #-- name))))

  (defn prepare [self]
    (for [fp self.fps]
      (.prepare fp))
    (setv self.pcap
          (doto (pypcap.pcap :name self.iface :promisc False :timeout-ms 100)
                (.setdirection pypcap.PCAP-D-IN)
                (.setfilter self.pcap-filter)
                (.setnonblock))
          self.packets       (list)
          self.send-finished False
          self.recv-queue    (deque)))

  (defn cleanup [self]
    (.close self.pcap)
    (.sort self.packets :key (fn [x] (get x 0)))
    (with [f (open self.output-all-pcap-path "wb")]
      (let [writer (Pcap.writer f)]
        (for [#(ts packet) self.packets]
          (let [#(msec sec) (modf ts)]
            (.write-packet writer packet :sec (int sec) :msec (int (* msec 1,000,000)))))))
    (with [f (open self.output-pcap-path "wb")]
      (let [writer (Pcap.writer f)]
        (for [#(seq fp) (enumerate self.fps)]
          (for [probe fp.probes]
            (.write-packet writer probe :sec seq :msec 1))
          (for [answer fp.answers]
            (.write-packet writer answer :sec seq :msec 2)))))
    (let [feats (dict)]
      (for [fp self.fps]
        (let [feat (.get-feat fp)]
          (when feat
            (for [#(k v) (.items feat)]
              (setv (get feats (.format "{}.{}" (. fp #-- class #-- name) k)) v)))))
      (with [f (open self.output-json-path "w")]
        (json.dump feats f))))

  (defn send-probe [self probe]
    (.append self.packets #((time) probe))
    (.sendpacket self.pcap probe))

  (defn recv-answers [self]
    (for [#(ts answer) (.readpkts self.pcap)]
      (.append self.packets #(ts answer))
      (.append self.recv-queue answer)))

  (defn get-answer-idseq [self parsed-answer]
    ;; return #(id seq) if it is a valid answer
    (raise NotImplementedError))

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
            (.send-probe self probe)
            (sleep self.send-interval))))
      (sleep self.send-timewait)
      (.dispatch-answers self)
      (let [count (cfor sum fp self.fps (not fp.answers))]
        (.info self.logger "[send] turn=%d, unanswered=%d/%d" i count (len self.fps))
        (when (= count 0)
          (break)))))

  (defn recver [self]
    (while (not self.send-finished)
      (.recv-answers self)
      (sleep 0.001)))

  (defn run [self]
    (for [fp self.fps]
      (.prepare fp))
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

  (defn [classmethod] main [cls]
    (let [args (parse-args [["-i" "--iface"]
                            ["-d" "--dst"]
                            ["-s" "--src"]
                            ["-n" "--next-hop"]
                            ["-D" "--mac-dst"]
                            ["-S" "--mac-src"]
                            ["-A" "--send-attempts" :type int :default 2]
                            ["-I" "--send-interval" :type float :default 0.01]
                            ["-T" "--send-timewait" :type float :default 0.2]
                            ["-o" "--output-path" :default "noefp"]
                            ["-l" "--list" :action "store_true" :default False]])]
      (let [ctx (cls :iface args.iface
                     :dst           args.dst
                     :src           args.src
                     :next-hop      args.next-hop
                     :mac-dst       args.mac-dst
                     :mac-src       args.mac-src
                     :send-attempts args.send-attempts
                     :send-interval args.send-interval
                     :send-timewait args.send-timewait
                     :output-path   args.output-path)]
        (logging.basicConfig
          :level   "INFO"
          :format  "%(asctime)s %(name)s %(levelname)s %(message)s"
          :datefmt "%H:%M:%S")
        (.log-info ctx)
        (unless args.list
          (.run ctx))))))



(defclass BaseIPv4FPCtx [FPCtx]
  (defn get-default-iface [self dst]
    (guess-iface-by-ipv4 dst))

  (defn [cached-property] default-route [self]
    (get-route-by-ipv4 self.dst))

  (defn [cached-property] default-mac-dst [self]
    (get-mac-by-ipv4 (if (= self.next-hop "0.0.0.0") self.dst self.next-hop)))

  (defn [property] pcap-filter [self]
    (.format "ip src {}" self.dst)))

(defclass BaseIPv6FPCtx [FPCtx]
  (defn get-default-iface [self dst]
    (guess-iface-by-ipv6 dst))

  (defn [cached-property] default-route [self]
    (get-route-by-ipv6 self.dst))

  (defn [cached-property] default-mac-dst [self]
    (get-mac-by-ipv6 (if (= self.next-hop "::") self.dst self.next-hop)))

  (defn [property] pcap-filter [self]
    (.format "ip6 src {}" self.dst)))



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

  (defn get-feat [self]
    ;; if answered, return a dict of #(k v)
    (raise NotImplementedError))

  (defn make-ip [self #** kwargs]
    (raise NotImplementedError))

  (defn make-ip-with-ether [self #** kwargs]
    (/ (Ether :src self.ctx.mac-src :dst self.ctx.mac-dst)
       (.make-ip self #** kwargs)))

  (defn make-ping [self [code 0] [data (bytes 32)]]
    (raise NotImplementedError))

  (defn make-udp [self]
    (UDP :src self.idseqB :dst self.idseqB))

  (defn make-tcp [self #** kwargs]
    (TCP :src self.idseqB :dst self.idseqB :seq self.idseqH #** kwargs))

  (defn build-pload [self pload #** kwargs]
    (let [packet (/ (.make-ip self #** kwargs) pload)]
      (.build packet)
      packet.pload))

  (defn build-ping [self [code 0] [data (bytes 32)] #** kwargs]
    (.build-pload self (.make-ping self code data) #** kwargs)))

(export
  :objects [idseq-packB idseq-unpackB idseq-packH idseq-unpackH
            FPCtx BaseIPv4FPCtx BaseIPv6FPCtx FP])
