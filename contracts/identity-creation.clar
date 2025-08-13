;; RefugeID Identity Creation Contract
;; Clarity v2 (latest syntax as of 2025)
;; Manages creation and maintenance of decentralized identities (DIDs) for displaced persons.
;; Stores encrypted personal data, supports updates, and integrates basic privacy features.
;; Emits events for auditing and includes admin controls for emergency management.

(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-INVALID-DATA u101)
(define-constant ERR-IDENTITY-EXISTS u102)
(define-constant ERR-NO-IDENTITY u103)
(define-constant ERR-PAUSED u104)
(define-constant ERR-ZERO-PRINCIPAL u105)
(define-constant ERR-INVALID-UPDATE u106)
(define-constant ERR-EXPIRED u107)
(define-constant ERR-INVALID-EXPIRY u108)

;; Contract metadata
(define-constant CONTRACT-NAME "RefugeID Identity Creation")
(define-constant VERSION "1.0.0")
(define-constant EXPIRY-BLOCKS u52560) ;; Approx 1 year (assuming 10-min blocks)

;; Admin and state variables
(define-data-var admin principal tx-sender)
(define-data-var paused bool false)
(define-data-var total-identities uint u0)

;; Identity storage: principal -> {encrypted-data: (buff 1024), creation-height: uint, expiry-height: uint}
(define-map identities principal {encrypted-data: (buff 1024), creation-height: uint, expiry-height: uint})

;; Approved issuers: map principals to bool (for credential linkage, extensible)
(define-map approved-issuers principal bool)

;; Private helper: is-admin
(define-private (is-admin)
  (is-eq tx-sender (var-get admin))
)

;; Private helper: ensure not paused
(define-private (ensure-not-paused)
  (asserts! (not (var-get paused)) (err ERR-PAUSED))
)

;; Private helper: validate data buffer
(define-private (validate-data (data (buff 1024)))
  (asserts! (> (len data) u0) (err ERR-INVALID-DATA))
  (ok true)
)

;; Private helper: check if identity is valid (exists and not expired)
(define-private (is-valid-identity (user principal))
  (match (map-get? identities user)
    some-identity (if (>= block-height (get expiry-height some-identity))
                    (err ERR-EXPIRED)
                    (ok some-identity))
    (err ERR-NO-IDENTITY)
  )
)

;; Transfer admin rights
(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (asserts! (not (is-eq new-admin tx-sender)) (err ERR-ZERO-PRINCIPAL)) ;; Prevent self-lockout example
    (var-set admin new-admin)
    (print {event: "admin-transferred", new-admin: new-admin})
    (ok true)
  )
)

;; Pause/unpause contract
(define-public (set-paused (pause bool))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (var-set paused pause)
    (print {event: "pause-status-changed", paused: pause})
    (ok pause)
  )
)

;; Add approved issuer (admin only)
(define-public (add-issuer (issuer principal))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (map-set approved-issuers issuer true)
    (print {event: "issuer-added", issuer: issuer})
    (ok true)
  )
)

;; Remove approved issuer (admin only)
(define-public (remove-issuer (issuer principal))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (map-delete approved-issuers issuer)
    (print {event: "issuer-removed", issuer: issuer})
    (ok true)
  )
)

;; Create a new identity
(define-public (create-identity (encrypted-data (buff 1024)) (custom-expiry uint))
  (begin
    (ensure-not-paused)
    (try! (validate-data encrypted-data))
    (asserts! (is-none (map-get? identities tx-sender)) (err ERR-IDENTITY-EXISTS))
    (asserts! (and (> custom-expiry u0) (<= custom-expiry EXPIRY-BLOCKS)) (err ERR-INVALID-EXPIRY))
    (let ((expiry (+ block-height custom-expiry)))
      (map-set identities tx-sender {
        encrypted-data: encrypted-data,
        creation-height: block-height,
        expiry-height: expiry
      })
      (var-set total-identities (+ (var-get total-identities) u1))
      (print {event: "identity-created", user: tx-sender, creation-height: block-height})
      (ok tx-sender) ;; Return DID as principal for simplicity
    )
  )
)

;; Update encrypted data (user only, if valid)
(define-public (update-identity (new-encrypted-data (buff 1024)))
  (begin
    (ensure-not-paused)
    (try! (validate-data new-encrypted-data))
    (let ((identity (try! (is-valid-identity tx-sender))))
      (map-set identities tx-sender (merge identity {encrypted-data: new-encrypted-data}))
      (print {event: "identity-updated", user: tx-sender})
      (ok true)
    )
  )
)

;; Extend expiry (user only, if valid)
(define-public (extend-expiry (additional-blocks uint))
  (begin
    (ensure-not-paused)
    (asserts! (> additional-blocks u0) (err ERR-INVALID-UPDATE))
    (let ((identity (try! (is-valid-identity tx-sender))))
      (let ((new-expiry (+ (get expiry-height identity) additional-blocks)))
        (asserts! (<= (- new-expiry (get creation-height identity)) EXPIRY-BLOCKS) (err ERR-INVALID-EXPIRY))
        (map-set identities tx-sender (merge identity {expiry-height: new-expiry}))
        (print {event: "expiry-extended", user: tx-sender, new-expiry: new-expiry})
        (ok true)
      )
    )
  )
)

;; Delete identity (user only)
(define-public (delete-identity)
  (begin
    (ensure-not-paused)
    (asserts! (is-some (map-get? identities tx-sender)) (err ERR-NO-IDENTITY))
    (map-delete identities tx-sender)
    (var-set total-identities (- (var-get total-identities) u1))
    (print {event: "identity-deleted", user: tx-sender})
    (ok true)
  )
)

;; Read-only: get identity details (for user or admin)
(define-read-only (get-identity (user principal))
  (match (map-get? identities user)
    some-identity (if (or (is-eq tx-sender user) (is-admin))
                    (ok some-identity)
                    (err ERR-NOT-AUTHORIZED))
    (err ERR-NO-IDENTITY)
  )
)

;; Read-only: check if issuer is approved
(define-read-only (is-approved-issuer (issuer principal))
  (ok (default-to false (map-get? approved-issuers issuer)))
)

;; Read-only: get total identities
(define-read-only (get-total-identities)
  (ok (var-get total-identities))
)

;; Read-only: get admin
(define-read-only (get-admin)
  (ok (var-get admin))
)

;; Read-only: is paused
(define-read-only (is-paused)
  (ok (var-get paused))
)

;; Read-only: get expiry blocks constant
(define-read-only (get-expiry-blocks)
  (ok EXPIRY-BLOCKS)
)

;; Additional helper: batch add issuers (admin only, for efficiency)
(define-public (batch-add-issuers (issuers (list 10 principal)))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (fold add-issuer-fold issuers (ok true))
  )
)

(define-private (add-issuer-fold (issuer principal) (prev (response bool uint)))
  (match prev
    success (begin
      (map-set approved-issuers issuer true)
      (print {event: "issuer-added-batch", issuer: issuer})
      (ok true)
    )
    error prev
  )
)