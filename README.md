# Kaphos Go Auth Package

This package is intended for internal use for authentication backends. 

To use, first initialise an object, passing in parameters for the configuration:

```go

import github.com/kaphos/auth

config := auth.Config{
    KMSPath:        "auth.keys",
    DBPath:         "auth.db",
    IdleTimeout:    time.Hour,
    ForcedTimeout:  time.Hour * 24,
    RmbMeTimeout:   time.Hour * 24 * 180,
    HashIterations: 7,
    HashMemory:     48,
}
authObj := auth.New(config)
```

Several functions are exported:

- `authObj.HashPassword` - Given a password, return the hash using the preset parameters and algorithm. 
- `authObj.AttemptLogin` - When a user submits a login form, checks if valid and creates the appropriate cookies
- `authObj.CheckLogin` - When a user attempts to access a protected endpoint, checks the user's cookies
- `authObj.Logout` - When a user wants to log out from their current session
- `authObj.LogoutAll` - When a user wants to log out from all sessions (removes 'Remember Me' sessions as well)