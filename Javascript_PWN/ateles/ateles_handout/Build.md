## Ateles

The current directory contains a non-debug js shell built with the provided patch, to help you develop your exploit.

The `docker_stuff` directory contains the the environment, the challenge is running on, in the remote server. Please do use this to test your exploits locally before trying it on the remote server.

Please note that on the remote server sandbox is disabled. Also, `javascript.options.ion.offthread_compilation` is set to false, to increase the realibility of your exploits. These settings can be tweaked in the `docker_stuff/firefox/vulnProfile/prefs.js` file.

The built firefox browser runs with the `vulnProfile` profile. (`docker_stuff/firefox/vulnProfile`)
