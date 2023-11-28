(require
  hiolib.rule :readers * *)

(import
  hiolib.struct *
  hpacket.inet *
  neofp.base *)

(defclass TCPFPCtx [BaseTCPFPCtx]
  (setv fp-classes (list)))

(defclass TCPFP [FP]
  (setv C 0
        E 0
        U 0
        A 0
        P 0
        R 0
        S 1                     ; S defualt to 1, unset it explicitly
        F 0
        win 64240               ; same as win11
        uptr 0)

  (setv ws 8)

  (defn [property] mss [self]
    (ecase self.ctx.ipver IPVer.V4 1460 IPVer.V6 1420))

  (defn make-opts [self]        ; same as win11
    [#(TCPOpt.MSS self.mss)
     #(TCPOpt.NOP b"")
     #(TCPOpt.WS  self.ws)
     #(TCPOpt.NOP b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.SAckOK b"")])

  (defn make-probe [self]
    (/ (.make-ip-with-ether self)
       (.make-tcp-with-target-port self
         :C self.C :E self.E :U self.U :A self.A :P self.P :R self.R :S self.S :F self.F
         :win self.win :uptr self.uptr :opts (.make-opts self)))))



(defclass [TCPFPCtx.register] Ctl [TCPFP])

(defclass [TCPFPCtx.register] Pload [TCPFP]
  (defn make-probe [self]
    (/ (#super make-probe) (bytes 20))))

(defclass [TCPFPCtx.register] FlagSA   [TCPFP] (setv A 1))
(defclass [TCPFPCtx.register] FlagSF   [TCPFP] (setv F 1))
(defclass [TCPFPCtx.register] FlagSR   [TCPFP] (setv R 1))
(defclass [TCPFPCtx.register] FlagSEC  [TCPFP] (setv E 1 C 1 uptr 0x1234))
(defclass [TCPFPCtx.register] FlagSUPF [TCPFP] (setv U 1 P 1 F 1 uptr 0x1234))
(defclass [TCPFPCtx.register] Flag0    [TCPFP] (setv S 0))
(defclass [TCPFPCtx.register] FlagA    [TCPFP] (setv S 0 A 1))
(defclass [TCPFPCtx.register] FlagF    [TCPFP] (setv S 0 F 1))
(defclass [TCPFPCtx.register] FlagR    [TCPFP] (setv S 0 R 1))
(defclass [TCPFPCtx.register] FlagEC   [TCPFP] (setv S 0 E 1 C 1 uptr 0x1234))
(defclass [TCPFPCtx.register] FlagUPF  [TCPFP] (setv S 0 U 1 P 1 F 1 uptr 0x1234))

(defclass [TCPFPCtx.register] ArgWin0     [TCPFP] (setv win     0))
(defclass [TCPFPCtx.register] ArgWin1     [TCPFP] (setv win     1))
(defclass [TCPFPCtx.register] ArgWin65535 [TCPFP] (setv win 65535))
(defclass [TCPFPCtx.register] ArgMSS0     [TCPFP] (setv mss     0))
(defclass [TCPFPCtx.register] ArgMSS1     [TCPFP] (setv mss     1))
(defclass [TCPFPCtx.register] ArgMSS65535 [TCPFP] (setv mss 65535))
(defclass [TCPFPCtx.register] ArgWS0      [TCPFP] (setv ws      0))
(defclass [TCPFPCtx.register] ArgWS1      [TCPFP] (setv ws      1))
(defclass [TCPFPCtx.register] ArgWS255    [TCPFP] (setv ws    255))



(defclass [TCPFPCtx.register] OptLenM1 [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.NOP b"")
     #(TCPOpt.MSS (int-pack 255 1)) ; len of mss from 4 to 3
     #(TCPOpt.NOP b"")
     #(TCPOpt.WS  self.ws)
     #(TCPOpt.NOP b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.SAckOK b"")]))

(defclass [TCPFPCtx.register] OptLenW2 [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.MSS self.mss)
     #(TCPOpt.WS  (int-pack 8 2)) ; len of ws from 3 to 4
     #(TCPOpt.NOP b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.SAckOK b"")]))

(defclass [TCPFPCtx.register] OptLenT4 [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.MSS self.mss)
     #(TCPOpt.NOP b"")
     #(TCPOpt.WS  self.ws)
     #(TCPOpt.NOP b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.SAckOK b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.TS (int-pack 0xffffffff 4)) ; len of ts from 4*2+2 to 4*1+2
     ]))

(defclass [TCPFPCtx.register] OptLenS2 [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.MSS self.mss)
     #(TCPOpt.NOP b"")
     #(TCPOpt.WS  self.ws)
     #(TCPOpt.SAckOK (bytes 2)) ; len of sackok from 2 to 4
     ]))



(defclass [TCPFPCtx.register] OptDupM11 [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.MSS self.mss)     ; dup1
     #(TCPOpt.NOP b"")
     #(TCPOpt.WS  self.ws)
     #(TCPOpt.NOP b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.SAckOK b"")
     #(TCPOpt.MSS self.mss)     ; dup1
     ]))

(defclass [TCPFPCtx.register] OptDupM10 [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.MSS self.mss)     ; dup1
     #(TCPOpt.NOP b"")
     #(TCPOpt.WS  self.ws)
     #(TCPOpt.NOP b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.SAckOK b"")
     #(TCPOpt.MSS 0)            ; dup0
     ]))

(defclass [TCPFPCtx.register] OptDupM01 [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.MSS 0)            ; dup0
     #(TCPOpt.NOP b"")
     #(TCPOpt.WS  self.ws)
     #(TCPOpt.NOP b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.SAckOK b"")
     #(TCPOpt.MSS self.mss)     ; dup1
     ]))

(defclass [TCPFPCtx.register] OptDupW11 [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.MSS self.mss)
     #(TCPOpt.NOP b"")
     #(TCPOpt.WS  self.ws)      ; dup1
     #(TCPOpt.NOP b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.SAckOK b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.WS  self.ws)      ; dup1
     ]))

(defclass [TCPFPCtx.register] OptDupW10 [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.MSS self.mss)
     #(TCPOpt.NOP b"")
     #(TCPOpt.WS  self.ws)      ; dup1
     #(TCPOpt.NOP b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.SAckOK b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.WS  0)            ; dup0
     ]))

(defclass [TCPFPCtx.register] OptDupW01 [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.MSS self.mss)
     #(TCPOpt.NOP b"")
     #(TCPOpt.WS  0)            ; dup0
     #(TCPOpt.NOP b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.SAckOK b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.WS  self.ws)      ; dup1
     ]))

(defclass [TCPFPCtx.register] OptDupS [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.MSS self.mss)
     #(TCPOpt.NOP b"")
     #(TCPOpt.WS  self.ws)
     #(TCPOpt.SAckOK b"")       ; dup
     #(TCPOpt.SAckOK b"")       ; dup
     ]))



(defclass [TCPFPCtx.register] OptOrdMW [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.MSS self.mss)
     #(TCPOpt.NOP b"")
     #(TCPOpt.WS  self.ws)]))

(defclass [TCPFPCtx.register] OptOrdWM [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.NOP b"")
     #(TCPOpt.WS  self.ws)
     #(TCPOpt.MSS self.mss)]))

(defclass [TCPFPCtx.register] OptOrdMS [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.MSS self.mss)
     #(TCPOpt.NOP b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.SAckOK b"")]))

(defclass [TCPFPCtx.register] OptOrdSM [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.NOP b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.SAckOK b"")
     #(TCPOpt.MSS self.mss)]))

(defclass [TCPFPCtx.register] OptOrdWS [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.NOP b"")
     #(TCPOpt.WS  self.ws)
     #(TCPOpt.NOP b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.SAckOK b"")]))

(defclass [TCPFPCtx.register] OptOrdSW [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.NOP b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.SAckOK b"")
     #(TCPOpt.NOP b"")
     #(TCPOpt.WS  self.ws)]))



(defclass [TCPFPCtx.register] OptPad010 [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.MSS self.mss)
     #(TCPOpt.NOP b"")
     #(TCPOpt.WS  self.ws)
     #(TCPOpt.NOP b"")          ; 0
     #(TCPOpt.SAckOK b"")       ; 1
     #(TCPOpt.NOP b"")          ; 0
     ]))

(defclass [TCPFPCtx.register] OptPad100 [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.MSS self.mss)
     #(TCPOpt.NOP b"")
     #(TCPOpt.WS  self.ws)
     #(TCPOpt.SAckOK b"")       ; 1
     #(TCPOpt.NOP b"")          ; 0
     #(TCPOpt.NOP b"")          ; 0
     ]))

(defclass [TCPFPCtx.register] OptPad1 [TCPFP]
  (defn make-opts [self]
    [#(TCPOpt.MSS self.mss)
     #(TCPOpt.WS self.ws)
     #(TCPOpt.SAckOK b"")]))



(defclass [TCPFPCtx.register] OptIvld0      [TCPFP] (defn make-opts [self] []))
(defclass [TCPFPCtx.register] OptIvldEOL    [TCPFP] (defn make-opts [self] [#(TCPOpt.EOL b"")]))
(defclass [TCPFPCtx.register] OptIvldEOL4   [TCPFP] (defn make-opts [self] [#(TCPOpt.EOL b"") #(TCPOpt.EOL b"") #(TCPOpt.EOL b"") #(TCPOpt.NOP b"")]))
(defclass [TCPFPCtx.register] OptIvldNOP4   [TCPFP] (defn make-opts [self] [#(TCPOpt.NOP b"") #(TCPOpt.NOP b"") #(TCPOpt.NOP b"") #(TCPOpt.NOP b"")]))
(defclass [TCPFPCtx.register] OptIvldSAck   [TCPFP] (defn make-opts [self] [#(TCPOpt.SAck [])]))
(defclass [TCPFPCtx.register] OptIvldSAck0  [TCPFP] (defn make-opts [self] [#(TCPOpt.SAck [0])]))
(defclass [TCPFPCtx.register] OptIvldSAck00 [TCPFP] (defn make-opts [self] [#(TCPOpt.SAck [0 0])]))

(defmain []
  (.main TCPFPCtx))
