# Specification Review: Implementation Questions

The technical specification is a strong statement of goals and safety principles. Before implementing cache reuse, resolve these points so the observer and sidecar format can be validated against one precise contract.

## Trust and provenance

The spec says committed JSON alone must not forge a trusted PASS, but its initial provenance model and the MVP do not define how trust is established. Specify the trusted producer, verification material, and behavior for local, cloned, and CI-generated sidecars. Until then, a matching sidecar must not authorize a skip.

## Environment identity

The fingerprint requires a stable runtime identity and declared environment inputs, but the exact fields and policy for unset variables, values, and platform variation are open. Define canonical serialization and ensure secret values are never persisted.

## Observation limits and external state

The spec lists candidate Linux tracing backends and filesystem operations without selecting a required coverage baseline. It also calls for conservative network detection without defining what counts as network access or how DNS, sockets, and mutable external services are classified. Define which missed or unsupported observations force execution.

## Process outcomes and CLI

Document the numeric status returned when a child is terminated by a signal, and distinguish that from `tm` internal errors. The CLI examples use both `tm -- <command>` and options before `--`; specify parsing, option ordering, and whether `--` is mandatory.

## Initial implementation boundary

The suggested module list is broad for a first increment. A useful first milestone is a transparent process wrapper with exit-status propagation, followed by an observer prototype and sidecar validation. Keep cache skipping disabled until provenance, observer failure handling, and the conservative fallback rules have an acceptance testable definition.
