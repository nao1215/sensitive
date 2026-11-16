// Package embargosentry masks complete Sentry events at the BeforeSend boundary.
// Assign NewBeforeSend to ClientOptions.BeforeSend. Errors and panics during
// event serialization or scanning drop the event. Attachments and envelopes
// added after this callback are outside this boundary; configure them separately.
package embargosentry
