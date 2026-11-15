// Package output implements the shared JSON boundary for the optional logger
// adapters. It is internal so the adapters can share one audited parser without
// adding SDK dependencies or another public runtime API to the root module.
package output
