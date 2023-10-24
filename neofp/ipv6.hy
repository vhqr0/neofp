(require
  hiolib.rule :readers * *)

(import
  scapy.all :as sp
  hpacket.inet *
  neofp.base *)

(defclass IPv6FPCtx [FPCtx]
  (setv fp-classes (list))

  (defn [property] default-iface [self]
    (get (.route sp.conf.route6 self.dst) 0))

  (defn [property] default-route [self]
    (let [route (.route sp.conf.route6 self.dst :dev self.iface)]
      (unless (= (get route 0) self.iface)
        (raise RuntimeError))
      route))

  (defn [property] default-mac-dst [self]
    (sp.getmacbyip6 (if (= self.next-hop "::") self.dst self.next-hop)))

  (defn [property] default-mac-src [self]
    (. (get sp.conf.ifaces self.iface) mac))

  (defn [property] pcap-filter [self]
    (.format "ip6 src {}" self.dst))

  (defn get-answer-idseq [self parsed-answer]
    (let [head (get parsed-answer ICMPv6)]
      (when head
        (setv head head.next-packet)
        (cond (isinstance head ICMPv6EchoRep)
              #(head.id head.seq)
              (isinstance head #(ICMPv6DestUnreach ICMPv6ParamProblem))
              (do
                (setv head head.next-packet)
                (when (isinstance head IPv6Error)
                  (idseq-unpackB head.fl))))))))

(defclass IPv6FP [FP]
  (defn get-feat [self]
    (when self.parsed-answers
      (let [ipv6 (get self.parsed-answers 0 IPv6)
            icmpv6 (get ipv6 ICMPv6)
            np icmpv6.next-packet]
        {"tc"   ipv6.tc
         "fl"   ipv6.fl
         "nh"   ipv6.nh
         "plen" ipv6.plen
         "type" icmpv6.type
         "code" icmpv6.code
         "arg"  (cond (isinstance np ICMPv6DestUnreach)
                      np.unused
                      (isinstance np ICMPv6ParamProblem)
                      np.ptr
                      True
                      0)})))

  (defn make-ip [self #** kwargs]
    (IPv6 :fl self.idseqB :src self.ctx.src :dst self.ctx.dst #** kwargs))

  (defn make-ping [self [code 0] [data (bytes 32)]]
    (/ (ICMPv6 :type ICMPv6Type.EchoReq :code code)
       (ICMPv6EchoReq :id self.ctx.id :seq self.seq)
       data))

  (defn make-frag [self #** kwargs]
    (IPv6Frag :id self.idseqB #** kwargs))

  (defn build-frag-2 [self [data None] [nh None] [flen None]]
    (when (is data None)
      (setv data (.make-ping self)))
    (when (isinstance data Packet)
      (when (is nh None)
        (setv nh (IPProto.resolve data)))
      (setv data (.build-pload self data)))
    (let [#(nh1 nh2) (cond (isinstance nh tuple)
                           nh
                           (isinstance nh int)
                           #(nh nh)
                           True
                           (raise TypeError))
          #(flen offset) (cond (isinstance flen tuple)
                               flen
                               (isinstance flen int)
                               #(flen flen)
                               (and (is flen None) (isinstance data tuple))
                               #((len (get data 0)) (len (get data 0)))
                               True
                               (raise TypeError))
          #(data1 data2) (cond (isinstance data tuple)
                               data
                               (isinstance data bytes)
                               #((cut data flen) (cut data offset None)))
          #(offset-div offset-mod) (divmod offset 8)]
      (when offset-mod
        (raise ValueError))
      [(/ (.make-ip-with-ether self)
          (.make-frag self :nh nh1 :M 1)
          data1)
       (/ (.make-ip-with-ether self)
          (.make-frag self :nh nh2 :offset offset-div)
          data2)])))


;;; ctl
;; control group.

(defclass [IPv6FPCtx.register] Ctl [IPv6FP]
  (defn make-probe [self]
    (/ (.make-ip-with-ether self)
       (.make-ping self))))

(defclass [IPv6FPCtx.register] CtlExtH [IPv6FP]
  (defn make-probe [self]
    (/ (.make-ip-with-ether self)
       (IPv6HBHOpts)
       (.make-ping self))))

(defclass [IPv6FPCtx.register] CtlExtD [IPv6FP]
  (defn make-probe [self]
    (/ (.make-ip-with-ether self)
       (IPv6DestOpts)
       (.make-ping self))))

(defclass [IPv6FPCtx.register] CtlExtF [IPv6FP]
  (defn make-probes [self]
    (.build-frag-2 self :flen 24)))


;;; ext family
;; name template: Ext{setname}{extspec}
;; extspec example:
;;   D2HD => IPv6DestOpts / IPv6HBHOpts / IPv6HBHOpts / IPv6DestOpts
;;   128D => IPv6DestOpts / IPv6DestOpts / ... (128x)

(defclass _ExtFP [IPv6FP]
  (defn make-ext [self]
    (raise NotImplementedError))
  (defn make-probe [self]
    (/ (.make-ip-with-ether self)
       (.make-ext self)
       (.make-ping self))))

(defclass _ExtDupFP [_ExtFP]
  (setv n None)
  (defn make-ext [self]
    (if (= self.n 1)
        (IPv6DestOpts)
        (/ #* (gfor _ (range self.n) (IPv6DestOpts))))))

(defclass [IPv6FPCtx.register] ExtUnk [IPv6FP]
  (defn make-probe [self]
    (/ (.make-ip-with-ether self :nh 150)
       (bytes 32))))

(defclass [IPv6FPCtx.register] ExtDup2D   [_ExtDupFP] (setv n   2))
(defclass [IPv6FPCtx.register] ExtDup8D   [_ExtDupFP] (setv n   8))
(defclass [IPv6FPCtx.register] ExtDup32D  [_ExtDupFP] (setv n  32))
(defclass [IPv6FPCtx.register] ExtDup128D [_ExtDupFP] (setv n 128))

(defclass [IPv6FPCtx.register] ExtOrdDH [_ExtFP]
  (defn make-ext [self]
    (/ (IPv6DestOpts) (IPv6HBHOpts))))

(defclass [IPv6FPCtx.register] ExtOrdHDH [_ExtFP]
  (defn make-ext [self]
    (/ (IPv6HBHOpts) (IPv6DestOpts) (IPv6HBHOpts))))

(defclass [IPv6FPCtx.register] ExtOrdF [_ExtFP]
  (defn make-ext [self]
    (.make-frag self)))

(defclass [IPv6FPCtx.register] ExtOrdFF [_ExtFP]
  (defn make-ext [self]
    (/ (.make-frag self) (.make-frag self))))

(defclass [IPv6FPCtx.register] ExtOrdDF [_ExtFP]
  (defn make-ext [self]
    (/ (IPv6DestOpts) (.make-frag self))))

(defclass [IPv6FPCtx.register] ExtOrdFD [_ExtFP]
  (defn make-ext [self]
    (/ (.make-frag self) (IPv6DestOpts))))

(defclass [IPv6FPCtx.register] ExtOrdFH [_ExtFP]
  (defn make-ext [self]
    (/ (.make-frag self) (IPv6HBHOpts))))


;;; opt family
;; name template: Opt{setname}{optspec}
;; optspec example:
;;   4FN => PadN(4, b"\xff\xff")
;;   4P1 => Pad1 / Pad1 / Pad1 / Pad1
;;   4N2 => PadN(2) / PadN(2)
;;   4NN => PadN(4)
;;   4U2 => Unk(2) / Unk(2)
;;   4UN => Unk(4)

(defclass _OptFP [_ExtFP]
  (defn make-opt [self]
    (raise NotImplementedError))
  (defn make-opts [self]
    [(.make-opt self)])
  (defn make-ext [self]
    (IPv6DestOpts :opts (.make-opts self))))

(defclass _OptUnkFP [_OptFP]
  (setv type None)
  (defn make-opt [self]
    #((+ (<< self.type 6) 0x37) (bytes 4))))

(defclass _OptPadP1FP [_OptFP]
  (setv n None)
  (defn make-opts [self]
    (lfor _ (range self.n) #(IPv6Opt.Pad1 b""))))

(defclass _OptPadN2FP [_OptFP]
  (setv n None)
  (defn make-opts [self]
    (lfor _ (range (>> self.n 1)) #(IPv6Opt.PadN 2))))

(defclass _OptPadNNFP [_OptFP]
  (setv n None)
  (defn make-opt [self]
    #(IPv6Opt.PadN self.n)))

(defclass _OptPadU2FP [_OptFP]
  (setv n None)
  (defn make-opts [self]
    (lfor _ (range (>> self.n 1)) #(0x37 b""))))

(defclass _OptPadUNFP [_OptFP]
  (setv n None)
  (defn make-opt [self]
    #(0x37 (bytes (- self.n 2)))))

(defclass [IPv6FPCtx.register] OptUnk00 [_OptUnkFP] (setv type 0))
(defclass [IPv6FPCtx.register] OptUnk01 [_OptUnkFP] (setv type 1))
(defclass [IPv6FPCtx.register] OptUnk10 [_OptUnkFP] (setv type 2))
(defclass [IPv6FPCtx.register] OptUnk11 [_OptUnkFP] (setv type 3))

(defclass [IPv6FPCtx.register] OptPad6FN [_OptFP]
  (defn make-opt [self]
    #(IPv6Opt.PadN b"\xff\xff\xff\xff")))

(defclass [IPv6FPCtx.register] OptPad2P1    [_OptPadP1FP] (setv n    2))
(defclass [IPv6FPCtx.register] OptPad4P1    [_OptPadP1FP] (setv n    4))
(defclass [IPv6FPCtx.register] OptPad6P1    [_OptPadP1FP] (setv n    6))
(defclass [IPv6FPCtx.register] OptPad8P1    [_OptPadP1FP] (setv n    8))
(defclass [IPv6FPCtx.register] OptPad32P1   [_OptPadP1FP] (setv n   32))
(defclass [IPv6FPCtx.register] OptPad128P1  [_OptPadP1FP] (setv n  128))
(defclass [IPv6FPCtx.register] OptPad1024P1 [_OptPadP1FP] (setv n 1024))

(defclass [IPv6FPCtx.register] OptPad2N2    [_OptPadN2FP] (setv n    2))
(defclass [IPv6FPCtx.register] OptPad4N2    [_OptPadN2FP] (setv n    4))
(defclass [IPv6FPCtx.register] OptPad6N2    [_OptPadN2FP] (setv n    6))
(defclass [IPv6FPCtx.register] OptPad8N2    [_OptPadN2FP] (setv n    8))
(defclass [IPv6FPCtx.register] OptPad32N2   [_OptPadN2FP] (setv n   32))
(defclass [IPv6FPCtx.register] OptPad128N2  [_OptPadN2FP] (setv n  128))
(defclass [IPv6FPCtx.register] OptPad1024N2 [_OptPadN2FP] (setv n 1024))

(defclass [IPv6FPCtx.register] OptPad2NN   [_OptPadNNFP] (setv n   2))
(defclass [IPv6FPCtx.register] OptPad4NN   [_OptPadNNFP] (setv n   4))
(defclass [IPv6FPCtx.register] OptPad6NN   [_OptPadNNFP] (setv n   6))
(defclass [IPv6FPCtx.register] OptPad8NN   [_OptPadNNFP] (setv n   8))
(defclass [IPv6FPCtx.register] OptPad32NN  [_OptPadNNFP] (setv n  32))
(defclass [IPv6FPCtx.register] OptPad128NN [_OptPadNNFP] (setv n 128))

(defclass [IPv6FPCtx.register] OptPad2U2    [_OptPadU2FP] (setv n    2))
(defclass [IPv6FPCtx.register] OptPad4U2    [_OptPadU2FP] (setv n    4))
(defclass [IPv6FPCtx.register] OptPad6U2    [_OptPadU2FP] (setv n    6))
(defclass [IPv6FPCtx.register] OptPad8U2    [_OptPadU2FP] (setv n    8))
(defclass [IPv6FPCtx.register] OptPad32U2   [_OptPadU2FP] (setv n   32))
(defclass [IPv6FPCtx.register] OptPad128U2  [_OptPadU2FP] (setv n  128))
(defclass [IPv6FPCtx.register] OptPad1024U2 [_OptPadU2FP] (setv n 1024))

(defclass [IPv6FPCtx.register] OptPad2UN   [_OptPadUNFP] (setv n   2))
(defclass [IPv6FPCtx.register] OptPad4UN   [_OptPadUNFP] (setv n   4))
(defclass [IPv6FPCtx.register] OptPad6UN   [_OptPadUNFP] (setv n   6))
(defclass [IPv6FPCtx.register] OptPad8UN   [_OptPadUNFP] (setv n   8))
(defclass [IPv6FPCtx.register] OptPad32UN  [_OptPadUNFP] (setv n  32))
(defclass [IPv6FPCtx.register] OptPad128UN [_OptPadUNFP] (setv n 128))


;;; frag family

(defclass ReverseMixin []
  (defn make-probes [self]
    (list (reversed (#super make-probes)))))

(defclass _FragExtFP [IPv6FP]
  (setv flen 24)

  (defn make-ext [self]
    (raise NotImplementedError))

  (defn make-probes [self]
    (.build-frag-2 self :data (/ (.make-ext self) (.make-ping self)) :flen self.flen)))

(defclass [IPv6FPCtx.register] FragRes1 [_ExtFP]
  (defn make-ext [self]
    (.make-frag self :res1 1)))

(defclass [IPv6FPCtx.register] FragRes2 [_ExtFP]
  (defn make-ext [self]
    (.make-frag self :res2 1)))

(defclass [IPv6FPCtx.register] FragExtF [_FragExtFP]
  (defn make-ext [self]
    (.make-frag self)))

(defclass [IPv6FPCtx.register] FragExtD [_FragExtFP]
  (defn make-ext [self]
    (IPv6DestOpts)))

(defclass [IPv6FPCtx.register] FragExtH [_FragExtFP]
  (defn make-ext [self]
    (IPv6HBHOpts)))

(defclass [IPv6FPCtx.register] FragHdrNh [IPv6FP]
  (defn make-probes [self]
    (.build-frag-2 self :nh #(IPProto.ICMPv6 IPProto.ICMPv4) :flen 24)))

(defclass [IPv6FPCtx.register] FragHdrNhR [ReverseMixin FragHdrNh])

(defclass [IPv6FPCtx.register] FragHdrExt [IPv6FP]
  (defn make-probes [self]
    (let [data1 (.build (IPv6DestOpts :nh IPProto.ICMPv6))
          data2 (.build-ping self)]
      (.build-frag-2 self :data #(data1 data2) :nh IPProto.ICMPv6))))

(defclass [IPv6FPCtx.register] FragLen4 [IPv6FP]
  (defn make-probes [self]
    (.build-frag-2 self :flen #(4 0))))

(defclass [IPv6FPCtx.register] FragLen12 [IPv6FP]
  (defn make-probes [self]
    (.build-frag-2 self :flen #(12 8))))

(defclass [IPv6FPCtx.register] FragLen20 [IPv6FP]
  (defn make-probes [self]
    (.build-frag-2 self :flen #(20 16))))

(defclass [IPv6FPCtx.register] FragLenTail0 [IPv6FP]
  (defn make-probes [self]
    (.build-frag-2 self #((.build-ping self) b"") :nh IPProto.ICMPv6)))

(defclass [IPv6FPCtx.register] FragLenTail8 [IPv6FP]
  (defn make-probes [self]
    (let [data (.build-ping self)]
      (.build-frag-2 self :data data :nh IPProto.ICMPv6 :flen #((len data) (- (len data) 8))))))

(defclass [IPv6FPCtx.register] FragLenTail4 [IPv6FP]
  (defn make-probes [self]
    (let [data (.build-ping self :data (bytes 36))]
      (.build-frag-2 self :data data :nh IPProto.ICMPv6 :flen #((len data) (- (len data) 4))))))

(defclass [IPv6FPCtx.register] FragOwt00 [IPv6FP]
  (defn make-probes [self]
    (.build-frag-2 self :flen #(24 16))))

(defclass [IPv6FPCtx.register] FragOwt10 [IPv6FP]
  (defn make-probes [self]
    (let [data (.build-ping self)
          data1 (+ (cut data 16) (* 8 b""))
          data2 (cut data 16 None)]
      (.build-frag-2 self :data #(data1 data2) :nh IPProto.ICMPv6 :flen #(24 16)))))

(defclass [IPv6FPCtx.register] FragOwt10R [ReverseMixin FragOwt10])

(defclass [IPv6FPCtx.register] FragOwt01 [IPv6FP]
  (defn make-probes [self]
    (let [data (.build-ping self)
          data1 (cut data 24)
          data2 (+ (* 8 b"") (cut data 16 None))]
      (.build-frag-2 self :data #(data1 data2) :nh IPProto.ICMPv6 :flen #(24 16)))))

(defclass [IPv6FPCtx.register] FragOwt01R [ReverseMixin FragOwt01])


;;; misc

(defclass [IPv6FPCtx.register] PingCode [IPv6FP]
  (defn make-probe [self]
    (/ (.make-ip-with-ether self)
       (.make-ping self :code 1))))

(defclass [IPv6FPCtx.register] UDPPort [IPv6FP]
  (defn make-probe [self]
    (/ (.make-ip-with-ether self)
       (.make-udp self)
       (bytes 32))))

(defmain []
  (.main IPv6FPCtx))
