(defsystem "lizard-burger"
  :version "0.1.0"
  :author "Olivier Lemelin"
  :license ""
  :depends-on (:cl-arrows :cl-ppcre :str)
  :components ((:module "src"
                :components
                ((:file "main")
                (:file "bytes-operations"))))
  :description "Tool to compile shellcode and help with general exploit generation.")
