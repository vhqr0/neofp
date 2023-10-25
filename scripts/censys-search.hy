(require
  hyrule :readers * *)

(import
  json
  censys.search [CensysHosts]
  hyrule *)

(defmain []
  (let [args (parse-args [["-o" "--output"]
                          ["-p" "--per-page" :type int :default 100]
                          ["-n" "--pages" :type int :default 10]
                          ["os"]])]
    (let [hosts (list)
          api (CensysHosts)
          query (.search api (.format "ip: \"::/0\" and operating_system.product: {}" args.os)
                         :per-page args.per-page
                         :pages args.pages)]
      (for [page query]
        (for [host page]
          (.append hosts host)))
      (with [f (open (or args.output (.format "{}.json" args.os)) "w")]
        (json.dump hosts f)))))
