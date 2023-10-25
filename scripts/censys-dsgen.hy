(require
  hyrule :readers * *)

(import
  json
  pathlib [Path]
  hyrule *)

(defmain []
  (let [args (parse-args [["-i" "--input" :default "censys"]
                          ["-o" "--output" :default "datasets.json"]])
        datasets (list)]
    (for [path (.glob (Path args.input) "*.json")]
      (with [f (.open path)]
        (for [host (json.load f)]
          (.append datasets [(get host "ip") path.stem]))))
    (with [f (open args.output "w")]
      (json.dump datasets f))))
