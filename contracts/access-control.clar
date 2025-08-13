;; RefugeID Access Control Contract
;; Clarity v2 (latest syntax as of 2025)
;; Manages selective disclosure and access to identity data using simulated ZKP (via proofs).
;; Supports granular permissions, logging, and integration with Identity Creation Contract.
;; Assumes off-chain ZKP generation; on-chain verifies signatures or simple proofs.

(define-constant ERR-NOT-AUTHORIZED u200)
(define-constant ERR-NO-ACCESS u201)
(define-constant ERR-INVALID-PROOF u202)
(define-constant ERR-PAUSED u203)
(define-constant ERR-ZERO-PRINCIPAL u204)
(define-constant ERR-EXPIRED-REQUEST u205)
(define-constant ERR-INVALID-REQUEST u206)
(define-constant ERR-MAX-REQUESTS u207)

;; Contract metadata
(define-constant CONTRACT-NAME "RefugeID Access Control")
(define-constant VERSION "1.0.0")
(define-constant REQUEST-TTL u144) ;; 1 day (144 blocks)
(define-constant MAX-ACTIVE-REQUESTS u100)

;; Admin and state variables
(define-data-var admin principal tx-sender)
(define-data-var paused bool false)
(define-data-var total-requests uint u0)

;; Access requests: request-id -> {requester: principal, owner: principal, fields: (list 5 (string-ascii 32)), proof: (buff 256), timestamp: uint, granted: bool}
(define-map access-requests uint {requester: principal, owner: principal, fields: (list 5 (string-ascii 32)), proof: (buff 256), timestamp: uint, granted: bool})

;; Permissions: owner -> requester -> allowed-fields (list)
(define-map permissions principal (map principal (list 5 (string-ascii 32))))

;; Private helper: is-admin
(define-private (is-admin)
  (is-eq tx-sender (var-get admin))
)

;; Private helper: ensure not paused
(define-private (ensure-not-paused)
  (asserts! (not (var-get paused)) (err ERR-PAUSED))
)

;; Private helper: validate proof (simulated; in real, use secp256k1 or advanced crypto)
(define-private (validate-proof (proof (buff 256)) (expected-hash (buff 32)))
  (asserts! (is-eq (hash160 proof) expected-hash) (err ERR-INVALID-PROOF)) ;; Placeholder for ZKP verify
  (ok true)
)

;; Private helper: get next request id
(define-private (get-next-request-id)
  (+ (var-get total-requests) u1)
)

;; Transfer admin rights
(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (asserts! (not (is-eq new-admin tx-sender)) (err ERR-ZERO-PRINCIPAL))
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

;; Request access (service provider requests from owner)
(define-public (request-access (owner principal) (fields (list 5 (string-ascii 32))) (proof (buff 256)))
  (begin
    (ensure-not-paused)
    (asserts! (> (len fields) u0) (err ERR-INVALID-REQUEST))
    (asserts! (<= (var-get total-requests) MAX-ACTIVE-REQUESTS) (err ERR-MAX-REQUESTS))
    (let ((request-id (get-next-request-id))
          (expected-hash (hash160 (concat (principal-to-ascii owner) (fold concat-strings fields (buff 0)))))) ;; Simulated hash
      (try! (validate-proof proof expected-hash))
      (map-set access-requests request-id {
        requester: tx-sender,
        owner: owner,
        fields: fields,
        proof: proof,
        timestamp: block-height,
        granted: false
      })
      (var-set total-requests request-id)
      (print {event: "access-requested", request-id: request-id, requester: tx-sender, owner: owner})
      (ok request-id)
    )
  )
)

;; Grant access (owner grants to requester)
(define-public (grant-access (request-id uint))
  (begin
    (ensure-not-paused)
    (match (map-get? access-requests request-id)
      some-request (begin
        (asserts! (is-eq tx-sender (get owner some-request)) (err ERR-NOT-AUTHORIZED))
        (asserts! (< (- block-height (get timestamp some-request)) REQUEST-TTL) (err ERR-EXPIRED-REQUEST))
        (asserts! (not (get granted some-request)) (err ERR-INVALID-REQUEST))
        (let ((requester (get requester some-request))
              (fields (get fields some-request)))
          (map-set permissions tx-sender {requester: fields})
          (map-set access-requests request-id (merge some-request {granted: true}))
          (print {event: "access-granted", request-id: request-id, owner: tx-sender, requester: requester})
          (ok true)
        )
      )
      (err ERR-NO-ACCESS)
    )
  )
)

;; Revoke access (owner revokes from requester)
(define-public (revoke-access (requester principal))
  (begin
    (ensure-not-paused)
    (asserts! (is-some (map-get? permissions tx-sender)) (err ERR-NO-ACCESS))
    (let ((owner-perms (unwrap! (map-get? permissions tx-sender) (err ERR-NO-ACCESS))))
      (asserts! (is-some (map-get? owner-perms requester)) (err ERR-NO-ACCESS))
      (map-set permissions tx-sender (map-delete owner-perms requester))
      (print {event: "access-revoked", owner: tx-sender, requester: requester})
      (ok true)
    )
  )
)

;; Verify access (anyone can check if requester has access to owner's fields)
(define-read-only (has-access (owner principal) (requester principal) (fields (list 5 (string-ascii 32))))
  (match (map-get? permissions owner)
    owner-perms (match (map-get? owner-perms requester)
                  allowed-fields (ok (fold check-field fields allowed-fields))
                  (err ERR-NO-ACCESS))
    (err ERR-NO-ACCESS)
  )
)

(define-private (check-field (field (string-ascii 32)) (acc bool))
  (and acc (is-some (index-of? acc field)))
)

;; Read-only: get request details (for involved parties or admin)
(define-read-only (get-request (request-id uint))
  (match (map-get? access-requests request-id)
    some-request (if (or (is-eq tx-sender (get owner some-request)) (is-eq tx-sender (get requester some-request)) (is-admin))
                   (ok some-request)
                   (err ERR-NOT-AUTHORIZED))
    (err ERR-NO-ACCESS)
  )
)

;; Read-only: get total requests
(define-read-only (get-total-requests)
  (ok (var-get total-requests))
)

;; Read-only: get admin
(define-read-only (get-admin)
  (ok (var-get admin))
)

;; Read-only: is paused
(define-read-only (is-paused)
  (ok (var-get paused))
)

;; Read-only: get request TTL
(define-read-only (get-request-ttl)
  (ok REQUEST-TTL)
)

;; Helper: cleanup expired requests (public, but incentivize via gas)
(define-public (cleanup-expired (request-ids (list 10 uint)))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (fold cleanup-fold request-ids (ok true))
  )
)

(define-private (cleanup-fold (request-id uint) (prev (response bool uint)))
  (match prev
    success (match (map-get? access-requests request-id)
      some-request (if (>= (- block-height (get timestamp some-request)) REQUEST-TTL)
                     (begin
                       (map-delete access-requests request-id)
                       (ok true)
                     )
                     (ok true))
      (ok true))
    error prev
  )
)

(define-private (concat-strings (a (buff 32)) (b (string-ascii 32)))
  (concat a (as-max-len? (string-to-buff b) u32))
)

(define-private (string-to-buff (s (string-ascii 32)))
  (fold concat-char (unwrap-panic (to-consensus-buff? s)) (buff 0))
)

(define-private (concat-char (c uint) (acc (buff 32)))
  (concat acc (int-to-buff c 1))
)

(define-private (int-to-buff (i uint) (len uint))
  (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? i)) u0 len))
)