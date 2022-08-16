# impfi
Import Finder - Finds DOS executables in a given directory, with the given extension, that have the given import(s).

Type impfi for more details.

Uses - Finding drivers that create driver objects, given the import IoCreateDevice.

## example
The following command will list driver files with the .sys extension that import either IoCreatedevice or ZwOpenProcess.

`impfi "C:\\Windows\\System32\\drivers" .sys IoCreateDevice ZwOpenProcess`
