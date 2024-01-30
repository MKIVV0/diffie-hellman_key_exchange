# .ONESHELL instructs make to invoke a single instance of the 
# shell and provide it with the entire recipe.
.ONESHELL: # Applies to every targets in the file!
prepare:
	rm -rf ./build/
	mkdir ./build/

build:
	cd ./build/
	cmake -S .. -B .
	cmake --build .
	echo "The project has been built!"
