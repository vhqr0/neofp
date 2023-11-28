(require
  hiolib.rule :readers * *)

(import
  neofp.tcp *)

(defclass NmapTCPFPCtx [BaseTCPFPCtx]
  (setv fp-classes (list)))

(defclass [NmapTCPFPCtx.register] S1 [TCPFP]
  (setv win 1)
  (defn make-opts [self]
    [#(TCPOpt.WS 10)
     #(TCPOpt.NOP b"")
     #(TCPOpt.MSS 1460)
     #(TCPOpt.TS #(0xffffffff 0))
     #(TCPOpt.SAckOK b"")]))

(defclass [NmapTCPFPCtx.register] S2 [TCPFP]
  (setv win 63)
  (defn make-opts [self]
    [#(TCPOpt.MSS 1400)
     #(TCPOpt.WS 0)
     #(TCPOpt.SAckOK b"")
     #(TCPOpt.TS #(0xffffffff 0))
     #(TCPOpt.EOL b"")]))

(defclass [NmapTCPFPCtx.register] S3 [TCPFP]
  (setv win 4)
  (defn make-opts [self]
    [#(TCPOpt.TS #(0xffffffff 0))
     #(TCPOpt.NOP b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.WS 5)
     #(TCPOpt.NOP b"")
     #(TCPOpt.MSS 640)]))

(defclass [NmapTCPFPCtx.register] S4 [TCPFP]
  (setv win 4)
  (defn make-opts [self]
    [#(TCPOpt.SAckOK b"")
     #(TCPOpt.TS #(0xffffffff 0))
     #(TCPOpt.WS 10)
     #(TCPOpt.EOL b"")]))

(defclass [NmapTCPFPCtx.register] S5 [TCPFP]
  (setv win 16)
  (defn make-opts [self]
    [#(TCPOpt.MSS 536)
     #(TCPOpt.SAckOK b"")
     #(TCPOpt.TS #(0xffffffff 0))
     #(TCPOpt.WS 10)
     #(TCPOpt.EOL b"")]))

(defclass [NmapTCPFPCtx.register] S6 [TCPFP]
  (setv win 512)
  (defn make-opts [self]
    [#(TCPOpt.MSS 265)
     #(TCPOpt.SAckOK b"")
     #(TCPOpt.TS #(0xffffffff 0))]))

(defclass [NmapTCPFPCtx.register] ECN [TCPFP]
  (setv E 1 C 1 win 3 uptr 0xf7f5)
  (defn make-opts [self]
    [#(TCPOpt.WS 10)
     #(TCPOpt.NOP b"")
     #(TCPOpt.MSS 1460)
     #(TCPOpt.SAckOK b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.NOP b"")]))

(defclass NmapTCPOpenPortFP [TCPFP]
  (setv ws 10)                  ; T2~T6: 10, T7: 15
  (defn make-opts [self]
    [#(TCPOpt.WS self.ws)
     #(TCPOpt.NOP b"")
     #(TCPOpt.MSS 265)
     #(TCPOpt.TS #(0xffffffff 0))
     #(TCPOpt.SAckOK b"")]))

(defclass NmapTCPClosePortFP [NmapTCPOpenPortFP]
  (defn make-probe [self]
    (/ (.make-ip-with-ether self)
       (.make-tcp-with-rand-port self
         :C self.C :E self.E :U self.U :A self.A :P self.P :R self.R :S self.S :F self.F
         :win self.win :uptr self.uptr :opts (.make-opts self)))))

(defclass [NmapTCPFPCtx.register] T2 [NmapTCPOpenPortFP]  (setv S 0 win 128))
(defclass [NmapTCPFPCtx.register] T3 [NmapTCPOpenPortFP]  (setv U 1 P 1 F 1 win 256))
(defclass [NmapTCPFPCtx.register] T4 [NmapTCPOpenPortFP]  (setv S 0 A 1 win 1024))
(defclass [NmapTCPFPCtx.register] T5 [NmapTCPClosePortFP] (setv S 1 win 31337))
(defclass [NmapTCPFPCtx.register] T6 [NmapTCPClosePortFP] (setv S 0 A 1 win 23768))
(defclass [NmapTCPFPCtx.register] T7 [NmapTCPClosePortFP] (setv S 0 U 1 P 1 F 1 win 65535 ws 15))

(defmain []
  (.main NmapTCPFPCtx))
