package logical

// Identity represents the identity information used by core to create implicit
// identity. Implicit identities are identities which are registered by Vault
// (and which are not already registered via the API by operators) when clients
// are authenticated against auth backends.
type Identity struct {
	// MountType is the backend mount's type to which this identity belongs to.
	MountType string `json:"mount_type" structs:"mount_type" mapstructure:"mount_type"`

	// MountID is the identifier of the mount entry to which this identity
	// belongs to.
	MountID string `json:"mount_id" structs:"mount_id" mapstructure:"mount_id"`

	// Name is the identifier of this identity in its authentication source.
	Name string `json:"name" structs:"name" mapstructure:"name"`
}
