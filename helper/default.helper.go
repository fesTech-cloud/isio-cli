package helper

import (
	starter "isio/boilerplate"
	golang "isio/folder_structure/golang_folder"
	"log"
	"os"
)

// CreateGolangFolder creates the default folder structure and files for a Go project.
func CreateGolangFolder(packageName string) {
	folders := golang.DefaultGolangCreateFolders()
	paths := golang.DefaultGolangWriteToFiles()

	createFolders(folders)
	createFiles(paths, packageName)
}

// createFolders takes a slice of folder paths and creates them.
func createFolders(folders []string) {
	for _, folder := range folders {
		if err := os.MkdirAll(folder, 0755); err != nil {
			handleError(err)
		}
	}
}

// createFiles takes a slice of file paths and creates them.
func createFiles(paths []string, packageName string) {
	starterFunc := starter.StarterGenerator(packageName)
	for index, filePath := range paths {
		starterCode := starterFunc[index]()
		file, err := os.Create(filePath)
		if err != nil {
			handleError(err)
			continue
		}
		defer file.Close()

		err = os.WriteFile(filePath, []byte(starterCode), 0666)
		if err != nil {
			handleError(err)
		}
	}
}

// handleError logs and exits the program on error.
func handleError(err error) {
	log.Fatalf("Error: %v", err)
}
