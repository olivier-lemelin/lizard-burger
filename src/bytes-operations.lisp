
(defpackage :lizard-burger.bytes-operations
  (:use :common-lisp))

(in-package :lizard-burger.bytes-operations)

(defconstant +byte-length+ 8)


(defun shl (x width bits)
  "Compute bitwise left shift of x by 'bits' bits, represented on 'width' bits"
  (logand (ash x bits)
          (1- (ash 1 width))))

(defun shr (x width bits)
  "Compute bitwise right shift of x by 'bits' bits, represented on 'width' bits"
  (logand (ash x (- bits))
          (1- (ash 1 width))))

(defun pop-right-byte (byte-seq bytes-length)
  (values (logand byte-seq #x000000FF)
          (shr byte-seq bytes-length +byte-length+)))

(defun pop-left-byte (byte-seq bytes-length)
  (values (shr (logand byte-seq #xFF000000) bytes-length (- bytes-length +byte-length+))
          (shl byte-seq bytes-length +byte-length+)))

(defun number->bytes-list (bytes bytes-length)
  (if (zerop bytes)
      nil
      (multiple-value-bind (byte bytes-remaining)
          (pop-left-byte bytes bytes-length)
        (cons byte
              (number->bytes-list bytes-remaining bytes-length)))))


(defun address (addr &key (reverse-endianness nil) (addr-length 32))
  (if reverse-endianness
      (reverse (number->bytes-list addr addr-length))
      (number->bytes-list addr addr-length)))

(defun numbers->hex-string (list)
  (loop for i in list
        collect (format nil "~X" i)))
