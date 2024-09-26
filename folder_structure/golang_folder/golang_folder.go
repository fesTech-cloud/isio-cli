package golangfolder

// getGolangFolders returns the list of folders for a Go project.
func DefaultGolangCreateFolders() []string {
	return []string{
		"hello/cmd/server",
		"hello/config",
		"hello/internal/handler",
		"hello/internal/model",
		"hello/internal/repository",
		"hello/internal/routes",
		"hello/internal/service",
		"hello/provider",
		"hello/x/interfacesx",
		"hello/x/middlewarex",
		"hello/x/healthx",
	}
}

// getDefaultGolangFiles returns the list of default Go files for a project.
func DefaultGolangWriteToFiles() []string {
	return []string{
		"hello/cmd/server/server.go",
		"hello/cmd/root.go",
		"hello/config/config.go",
		"hello/config/constant.go",
		"hello/internal/handler/user.handler.go",
		"hello/internal/service/user.service.go",
		"hello/internal/model/user.model.go",
		"hello/internal/repository/user.repository.go",
		"hello/internal/routes/user.routes.go",
		"hello/provider/provider.go",
		"hello/x/interfacesx/interfacesx.go",
		"hello/x/middlewarex/middlewarex.go",
		"hello/x/healthx/health.go",
		"hello/app.env",
		"hello/main.go",
		"hello/.gitignore",
	}
}
