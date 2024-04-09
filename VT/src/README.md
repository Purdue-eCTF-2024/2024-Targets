# sp2024_ectf

## Build Deployment 
`ectf_build_depl -d ./`

# Build Firmware 
`ectf_build_ap -d ./ -on ap --p 123456 -c 2 -ids "0x11111124, 0x11111125" -b "Test boot message" -t 0123456789abcdef -od build `

`ectf_build_comp -d ./ -on comp1 -od build -id 0x11111124 -b "Component boot" -al "McLean" -ad "08/08/08" -ac "Fritz"`

`ectf_build_comp -d ./ -on comp2 -od build -id 0x11111125 -b "Component boot" -al "McLean" -ad "08/08/08" -ac "Fritz1"`