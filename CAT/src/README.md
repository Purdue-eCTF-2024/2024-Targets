                                                     CAT-2024 ECTF DESIGN Document

   DESIGN DOCUMENT
This year's platform for the competition is Analog Devices’ MAX78000 FTHR board, which features advanced functionality. The aim of the eCTF_2024 competition is to develop software to protect medical devices against supply chain attacks.
The Medical Infrastructure Supply Chain Challenge (MISC) consists of an application processor (AP), two components connected by an I2C bus, and a development board.Medical devices can be repaired in a trusted facility, where valid components from the secure production unit can replace faulty ones.
This documentation will help ensure that functional and safety requirements are applied to our device.First of all, we would like to inform you about the use of the architecture proposed by the MITRE organization.
Our team has to design a secure method for verifying the authenticity of the chips used and guaranteeing the ongoing security of devices in operation.

1. Platform and Architecture:

The Application Processor (AP) is the "brain" of the medical device. It manages all communications with the host computer, orchestrates the MISC functionalities to be implemented, and performs all the processing required to keep the device running during normal operation after start-up. As part of the MISC protocol, the access point is responsible for guaranteeing the integrity of the device

The Components represent the many additional chips that may be found on a medical device including sensors that take measurements and actuators that interact with the patient. The components rely on the AP to ensure the integrity of the device.

	



2. Security objectives:
The main security objectives are as follows:
Verification of the authenticity of the chips used.
Guarantee the ongoing security of devices in operation.
Prevent injection attacks, buffer overflows and other vulnerabilities. 

3.1 Application Processor (AP):
Role: Manage communications, orchestrate MISC functionality, ensure integrity.
Vulnerabilities: *poor token and pin management*, Buffer overflows ,lack of input validation 
Fixes: handle commands forever by creating a specified list of preboot command and remove newline character from input and fixe the buff's length included the recv_input() fonction 


3.2 Host Messaging Library:
Files: inc/host_messaging.h, src/host_messaging.c
Role: Format messages between AP and host tools.
Vulnerabilities: Injection, buffer overflow.
Fixes: in the recv_input() fonction we replace gets’ function by fgets() and fixed the exact size of variables 


3.3 Simple I2C Library:
Files: inc/simple_i2c_controller.h, src/simple_i2c_controller.c, inc/simple_i2c_peripheral.h, src/simple_i2c_peripheral.c
Role: Manages I2C communication with the MAX78000.
Vulnerabilities: Unverified I2C address, missing error handling, uncontrolled access to registers, unvalidated inputs, reentrance attacks.
Fixes: Fixed the packet length to 64 in to the simple_i2c_peripheral.h file, Added checks, limited access to registers,reentrance attacks.


3.4 Board Link Library:
Files: inc/board_link.h, src/board_link.c
Role: Send arbitrary data messages between AP and components.
Vulnerabilities: unchecked packet length, denial of service, I2C address spoofing.
Fixes: verify if the length  packet didn't exceed the MAX_I2C_MESSAGE_LEN defined to 64.


3.5 Simple Flash Library:
Files: inc/simple_flash.h, src/simple_flash.c
Role: Interface with MAX78000FTHR flash memory.
Vulnerabilities: unvalidated inputs, insufficient error handling, unprevented buffer overflows, denial of service.
Corrections : Input validation, improved error handling, overflow protection, transaction limiting.

3.6 Components and ap "ectf_params.h" management: 
Files: Component.c and application_processor.c
Role: Storage the informations about the Ap_pin, Ap_Token and the attestation_data, used to be included in both source files
for comparison 
Vulnerabilities: information are stored in clear, poor token and pin management 
Fixes: manage this file generation by configuring the deployment/makefile







