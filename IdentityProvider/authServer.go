package identityprovider

// IdentityProviderConfig represents the structure of the identity provider configuration in the YAML file

type IdentityProviderConfig struct {
	IdentityProviders []struct {
		Name         string   `yaml:"name"`
		ClientID     string   `yaml:"clientID"`
		ClientSecret string   `yaml:"clientSecret"`
		RedirectURL  string   `yaml:"redirectURL"`
		AuthURL      string   `yaml:"authURL"`
		TokenURL     string   `yaml:"tokenURL"`
		Scopes       []string `yaml:"scopes"`
	} `yaml:"identityProviders"`
}
