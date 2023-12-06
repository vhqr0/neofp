(require
  hiolib.rule :readers * *)

(import
  csv
  operator
  itertools [chain]
  numpy :as np
  sklearn.ensemble [RandomForestClassifier]
  joblib)

(defn unzip-2 [it]
  (let [#(xs ys) #((list) (list))]
    (for [#(x y) it]
      (.append xs x)
      (.append ys y))
    #(xs ys)))

(defn load-dataset [path]
;;; dataset format:
  ;;
  ;; labels           | feat-name1 | feat-name2 | feat-name3 | ...
  ;; -----------------|------------|------------|------------|----
  ;; label1.sublabel1 | feat-1-1   | feat-1-2   | feat-1-3   | ...
  ;; label2           | feat-2-1   | feat-2-2   | feat-2-3   | ...
  ;;
  ;; return:
  ;;   - feat-names: feat-name1, feat-name2, feat-name3, ...
  ;;   - labels: [label1, sublabel1], [label2], ...
  ;;   - feats: [feat-1-1, feat-1-2, feat-1-3, ...], [feat-2-1, feat-2-2, feat-2-3, ...], ...

  (with [f (open path)]
    (let [reader (csv.reader f)
          header (next reader)
          data (list reader)]
      #((cut header 1 None)
         (lfor row data (tuple (.split (get row 0) ".")))
        (lfor row data (list (map int (cut row 1 None))))))))

(defclass SingleLayerModel []
  (defn #-- init [self label-names feat-names _model]
    (setv self.label-names label-names
          self.feat-names feat-names
          self._model _model))

  (defn predict-proba [self feat]
    (when (isinstance feat dict)
      (setv feat (lfor name self.feat-names (.get feat name 0))))
    #(self.label-names (get (.predict-proba self._model (np.array [feat])) 0)))

  (defn [classmethod] train [cls feat-names labels feats [model-factory RandomForestClassifier]]
    (setv label-names (tuple (set labels))
          feat-names (tuple feat-names))

    (let [name-indexes (dfor #(i name) (enumerate label-names) name i)]
      (setv labels (lfor label labels (get name-indexes label))))

    (setv model (doto (model-factory)
                      (.fit (np.array feats) (np.array labels))))

    (cls label-names feat-names model)))

(defclass MultiLayerModel []
  (defn #-- init [self _model _submodels]
    (setv self._model _model
          self._submodels _submodels))

  (defn predict-proba-tree [self feat [proba-limit 0.5] [proba-base 1.0]]
    (->> (zip #* (.predict-proba self._model feat))
         (ap-map #((get it 0) (* (get it 1) proba-base)))
         (ap-filter (>= (get it 1) proba-limit))
         (map #%(let [#(sublabel proba) %1]
                  #(sublabel proba (ap-if (get self._submodels sublabel)
                                          (.predict-proba-tree it feat proba-limit proba)))))
         (list)))

  (defn predict-proba [self feat [proba-limit 0.5]]
    (let [#(labels probas) #((list) (list))]
      (defn _walk [tree path]
        (when tree
          (let [#(sublabel proba children) tree
                path #(#* path sublabel)]
            (.append labels path)
            (.append probas proba)
            (when children
              (ap-each children
                       (_walk it path))))))
      (_walk #("" 1.0 (.predict-proba-tree self feat proba-limit)) #())
      #((list (ap-map (.join "." (chain #* (cut it 1 None))) (cut labels 1 None)))
         (cut probas 1 None))))

  (defn dump [self path]
    (joblib.dump self path))

  (defn [classmethod] load [cls path]
    (let [model (joblib.load path)]
      (unless (isinstance model cls)
        (raise RuntimeError))
      model))

  (defn [classmethod] train [cls feat-names labels feats [model-factory RandomForestClassifier]]
    (setv #(labels feats) (unzip-2 (filter (operator.itemgetter 0) (zip labels feats)))
          sublabels (list (ap-map #((get it 0)) labels))
          sublabel-set (set sublabels))

    (while (<= (len sublabel-set) 1)
      (unless sublabel-set
        (return None))
      ;; merge single sublabels, pop origin sublabel first
      (setv labels (list (map (operator.itemgetter #s 1:) labels)))
      (let [base-sublabel (get sublabels 0)]
        (setv #(labels feats) (unzip-2 (filter (operator.itemgetter 0) (zip labels feats)))
              sublabels (list (ap-map #(#* base-sublabel (get it 0)) labels))
              sublabel-set (set sublabels))))

    (cls (.train SingleLayerModel feat-names sublabels feats model-factory)
         (dfor sublabel sublabel-set
               sublabel (.train cls
                                feat-names
                                #* (unzip-2 (->> (zip labels feats)
                                                 (ap-filter (= (get it 0 0) (get sublabel -1)))
                                                 (ap-map #((cut (get it 0) 1 None) (get it 1)))))
                                model-factory)))))

(export
  :objects [load-dataset SingleLayerModel MultiLayerModel])
