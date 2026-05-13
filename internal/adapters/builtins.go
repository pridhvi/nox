package adapters

func init() {
	Register(NewHTTPProbe())
	Register(NewSecurityHeaders())
	Register(NewNmap())
	Register(NewFFUF())
	Register(NewSQLMap())
	Register(NewDalfox())
}
