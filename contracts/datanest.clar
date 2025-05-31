;; DataNest Secure Storage
;; This contract manages document storage, access control, and audit trail for business documents on the Stacks blockchain.
;; It allows businesses to register, store document references, manage access permissions, and maintain an immutable
;; audit log of all document interactions, creating a secure and transparent document management system.

;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-BUSINESS-ALREADY-EXISTS (err u101))
(define-constant ERR-BUSINESS-NOT-FOUND (err u102))
(define-constant ERR-DOCUMENT-ALREADY-EXISTS (err u103))
(define-constant ERR-DOCUMENT-NOT-FOUND (err u104))
(define-constant ERR-USER-NOT-FOUND (err u105))
(define-constant ERR-INVALID-PERMISSION-LEVEL (err u106))
(define-constant ERR-NO-ACCESS (err u107))
(define-constant ERR-INVALID-ACTION (err u108))

;; Permission levels
(define-constant PERMISSION-NONE u0)
(define-constant PERMISSION-VIEW u1)
(define-constant PERMISSION-EDIT u2)
(define-constant PERMISSION-ADMIN u3)
(define-constant PERMISSION-OWNER u4)

;; Action types for audit log
(define-constant ACTION-CREATE u1)
(define-constant ACTION-VIEW u2)
(define-constant ACTION-EDIT u3)
(define-constant ACTION-SHARE u4)
(define-constant ACTION-DELETE u5)

;; Data maps

;; Stores registered businesses and their owners
(define-map businesses
  { business-id: (string-ascii 64) }
  { 
    owner: principal,
    name: (string-ascii 256),
    registration-time: uint,
    active: bool
  }
)

;; Stores document metadata
(define-map documents
  { business-id: (string-ascii 64), document-id: (string-ascii 64) }
  {
    name: (string-ascii 256),
    description: (string-utf8 500),
    document-hash: (buff 32), ;; Hash of the document (points to off-chain storage)
    document-type: (string-ascii 64),
    creation-time: uint,
    last-modified: uint,
    version: uint,
    active: bool
  }
)

;; Manages access permissions for users to documents
(define-map document-permissions
  { business-id: (string-ascii 64), document-id: (string-ascii 64), user: principal }
  {
    permission-level: uint,
    granted-by: principal,
    granted-at: uint
  }
)

;; Maintains a comprehensive audit trail of all document interactions
(define-map audit-logs
  { business-id: (string-ascii 64), document-id: (string-ascii 64), log-id: uint }
  {
    user: principal,
    action: uint, ;; Action type (create, view, edit, share, delete)
    timestamp: uint,
    details: (string-utf8 500)
  }
)

;; Tracks the next audit log ID for each document
(define-map audit-log-counters
  { business-id: (string-ascii 64), document-id: (string-ascii 64) }
  { next-id: uint }
)

;; Private functions

;; Gets the next audit log ID and increments the counter
(define-private (get-next-audit-log-id (business-id (string-ascii 64)) (document-id (string-ascii 64)))
  (let ((counter (default-to { next-id: u1 } (map-get? audit-log-counters { business-id: business-id, document-id: document-id }))))
    (begin
      (map-set audit-log-counters 
        { business-id: business-id, document-id: document-id }
        { next-id: (+ (get next-id counter) u1) }
      )
      (get next-id counter)
    )
  )
)

;; Creates a new audit log entry
(define-private (log-audit-event
  (business-id (string-ascii 64))
  (document-id (string-ascii 64))
  (user principal)
  (action uint)
  (details (string-utf8 500))
)
  (let ((log-id (get-next-audit-log-id business-id document-id)))
    (map-set audit-logs
      { business-id: business-id, document-id: document-id, log-id: log-id }
      {
        user: user,
        action: action,
        timestamp: block-height,
        details: details
      }
    )
    true
  )
)

;; Checks if a user has sufficient permission for a document
(define-private (has-permission
  (business-id (string-ascii 64))
  (document-id (string-ascii 64))
  (user principal)
  (required-permission uint)
)
  (let (
    (business-data (map-get? businesses { business-id: business-id }))
    (permission-data (map-get? document-permissions { business-id: business-id, document-id: document-id, user: user }))
  )
    (if (is-none business-data)
      false
      (if (is-eq (get owner (unwrap-panic business-data)) user)
        true ;; Business owner has full access
        (if (is-none permission-data)
          false
          (>= (get permission-level (unwrap-panic permission-data)) required-permission)
        )
      )
    )
  )
)

;; Validates if a document exists
(define-private (document-exists (business-id (string-ascii 64)) (document-id (string-ascii 64)))
  (is-some (map-get? documents { business-id: business-id, document-id: document-id }))
)

;; Public functions

;; Registers a new business
(define-public (register-business (business-id (string-ascii 64)) (name (string-ascii 256)))
  (let ((existing-business (map-get? businesses { business-id: business-id })))
    (if (is-some existing-business)
      ERR-BUSINESS-ALREADY-EXISTS
      (begin
        (map-set businesses
          { business-id: business-id }
          {
            owner: tx-sender,
            name: name,
            registration-time: block-height,
            active: true
          }
        )
        (ok true)
      )
    )
  )
)

;; Adds a new document to a business
(define-public (add-document
  (business-id (string-ascii 64))
  (document-id (string-ascii 64))
  (name (string-ascii 256))
  (description (string-utf8 500))
  (document-hash (buff 32))
  (document-type (string-ascii 64))
)
  (let ((business-data (map-get? businesses { business-id: business-id })))
    (if (is-none business-data)
      ERR-BUSINESS-NOT-FOUND
      (if (not (is-eq (get owner (unwrap-panic business-data)) tx-sender))
        ERR-NOT-AUTHORIZED
        (if (document-exists business-id document-id)
          ERR-DOCUMENT-ALREADY-EXISTS
          (begin
            ;; Add the document
            (map-set documents
              { business-id: business-id, document-id: document-id }
              {
                name: name,
                description: description,
                document-hash: document-hash,
                document-type: document-type,
                creation-time: block-height,
                last-modified: block-height,
                version: u1,
                active: true
              }
            )
            ;; Auto-assign owner permission
            (map-set document-permissions
              { business-id: business-id, document-id: document-id, user: tx-sender }
              {
                permission-level: PERMISSION-OWNER,
                granted-by: tx-sender,
                granted-at: block-height
              }
            )
            ;; Log the creation
            (log-audit-event business-id document-id tx-sender ACTION-CREATE u"Document created")
            (ok true)
          )
        )
      )
    )
  )
)

;; Updates an existing document
(define-public (update-document
  (business-id (string-ascii 64))
  (document-id (string-ascii 64))
  (name (string-ascii 256))
  (description (string-utf8 500))
  (document-hash (buff 32))
  (document-type (string-ascii 64))
)
  (let (
    (document-data (map-get? documents { business-id: business-id, document-id: document-id }))
  )
    (if (is-none document-data)
      ERR-DOCUMENT-NOT-FOUND
      (if (not (has-permission business-id document-id tx-sender PERMISSION-EDIT))
        ERR-NOT-AUTHORIZED
        (begin
          (map-set documents
            { business-id: business-id, document-id: document-id }
            {
              name: name,
              description: description,
              document-hash: document-hash,
              document-type: document-type,
              creation-time: (get creation-time (unwrap-panic document-data)),
              last-modified: block-height,
              version: (+ (get version (unwrap-panic document-data)) u1),
              active: true
            }
          )
          (log-audit-event business-id document-id tx-sender ACTION-EDIT u"Document updated")
          (ok true)
        )
      )
    )
  )
)

;; Grants permission to a user for a document
(define-public (grant-document-permission
  (business-id (string-ascii 64))
  (document-id (string-ascii 64))
  (user principal)
  (permission-level uint)
)
  (if (not (has-permission business-id document-id tx-sender PERMISSION-ADMIN))
    ERR-NOT-AUTHORIZED
    (if (not (document-exists business-id document-id))
      ERR-DOCUMENT-NOT-FOUND
      (if (or (< permission-level PERMISSION-VIEW) (> permission-level PERMISSION-ADMIN))
        ERR-INVALID-PERMISSION-LEVEL
        (begin
          (map-set document-permissions
            { business-id: business-id, document-id: document-id, user: user }
            {
              permission-level: permission-level,
              granted-by: tx-sender,
              granted-at: block-height
            }
          )
          (log-audit-event 
            business-id 
            document-id 
            tx-sender 
            ACTION-SHARE 
            u"Permission granted to user"
          )
          (ok true)
        )
      )
    )
  )
)

;; Revokes permission from a user for a document
(define-public (revoke-document-permission
  (business-id (string-ascii 64))
  (document-id (string-ascii 64))
  (user principal)
)
  (if (not (has-permission business-id document-id tx-sender PERMISSION-ADMIN))
    ERR-NOT-AUTHORIZED
    (if (not (document-exists business-id document-id))
      ERR-DOCUMENT-NOT-FOUND
      (begin
        (map-delete document-permissions { business-id: business-id, document-id: document-id, user: user })
        (log-audit-event 
          business-id 
          document-id 
          tx-sender 
          ACTION-SHARE 
          u"Permission revoked"
        )
        (ok true)
      )
    )
  )
)

;; Marks a document access (for audit purposes)
(define-public (access-document
  (business-id (string-ascii 64))
  (document-id (string-ascii 64))
)
  (if (not (has-permission business-id document-id tx-sender PERMISSION-VIEW))
    ERR-NO-ACCESS
    (if (not (document-exists business-id document-id))
      ERR-DOCUMENT-NOT-FOUND
      (begin
        (log-audit-event business-id document-id tx-sender ACTION-VIEW u"Document accessed")
        (ok true)
      )
    )
  )
)

;; Soft deletes a document (marks as inactive)
(define-public (delete-document
  (business-id (string-ascii 64))
  (document-id (string-ascii 64))
)
  (let (
    (document-data (map-get? documents { business-id: business-id, document-id: document-id }))
  )
    (if (is-none document-data)
      ERR-DOCUMENT-NOT-FOUND
      (if (not (has-permission business-id document-id tx-sender PERMISSION-ADMIN))
        ERR-NOT-AUTHORIZED
        (begin
          (map-set documents
            { business-id: business-id, document-id: document-id }
            (merge (unwrap-panic document-data) { active: false })
          )
          (log-audit-event business-id document-id tx-sender ACTION-DELETE u"Document deleted")
          (ok true)
        )
      )
    )
  )
)

;; Read-only functions

;; Gets business information
(define-read-only (get-business-info (business-id (string-ascii 64)))
  (map-get? businesses { business-id: business-id })
)

;; Gets document information
(define-read-only (get-document-info (business-id (string-ascii 64)) (document-id (string-ascii 64)))
  (map-get? documents { business-id: business-id, document-id: document-id })
)

;; Checks the permission level of a user for a document
(define-read-only (get-user-permission (business-id (string-ascii 64)) (document-id (string-ascii 64)) (user principal))
  (let (
    (business-data (map-get? businesses { business-id: business-id }))
    (permission-data (map-get? document-permissions { business-id: business-id, document-id: document-id, user: user }))
  )
    (if (is-none business-data)
      (ok PERMISSION-NONE)
      (if (is-eq (get owner (unwrap-panic business-data)) user)
        (ok PERMISSION-OWNER)
        (if (is-none permission-data)
          (ok PERMISSION-NONE)
          (ok (get permission-level (unwrap-panic permission-data)))
        )
      )
    )
  )
)

;; Gets a specific audit log entry
(define-read-only (get-audit-log-entry (business-id (string-ascii 64)) (document-id (string-ascii 64)) (log-id uint))
  (map-get? audit-logs { business-id: business-id, document-id: document-id, log-id: log-id })
)

;; Helper function to convert uint to ASCII string (simplified for demo purposes)
(define-private (uint-to-ascii (value uint))
  (concat "u" (int-to-ascii value))
)

;; Helper function to convert int to ASCII string (simplified for demo purposes)
(define-private (int-to-ascii (value uint))
  (unwrap-panic (element-at 
    (list "0" "1" "2" "3" "4" "5" "6" "7" "8" "9" "10" "11" "12" "13" "14" "15")
    (if (> value u15) u0 value)
  ))
)

;; Helper function to convert principal to string representation (simplified for demo purposes)
(define-private (principal-to-buff32 (user principal))
  (begin
    (ok 0x0000000000000000000000000000000000000000000000000000000000000000)
  )
)