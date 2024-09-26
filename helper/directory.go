package helper

type fileDirectory string

const (
	server         fileDirectory = "cmd/server/server.go"
	root           fileDirectory = "cmd/root.go"
	config         fileDirectory = "config/config.go"
	constant       fileDirectory = "config/constant.go"
	userService    fileDirectory = "internal/service/user.service.go"
	userModel      fileDirectory = "internal/model/user.model.go"
	userRepository fileDirectory = "internal/repository/user.repository.go"
	userRoutes     fileDirectory = "internal/routes/user.routes.go"
	provider       fileDirectory = "provider/provider.go"
	interfacesx    fileDirectory = "x/interfacesx/interfacesx.go"
	middlewarex    fileDirectory = "x/middlewarex/validuser.go"
	health         fileDirectory = "x/healthx/health.go"
	env            fileDirectory = "app.env"
	main           fileDirectory = "main.go"
	gitignore      fileDirectory = ".gitignore"
)
