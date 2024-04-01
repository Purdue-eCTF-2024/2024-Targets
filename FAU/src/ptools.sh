#! /bin/bash

# AP BUILD PARAMETERS
ap_design="."
ap_output_name="ap"
ap_output_dir="build"
ap_pin="123456"
ap_token="0123456789abcdef"
ap_component_cnt="2"
ap_component_ids="0x11111124, 0x11111125"
ap_boot_message="AP Boot!"

# COMPONENT 1 BUILD PARAMETERS
cmp1_design="."
cmp1_output_name="cmp1"
cmp1_output_dir="build"
cmp1_component_id="0x11111124"
cmp1_boot_message="Component 1 Boot!"
cmp1_attest_loc="ATST_LOC1"
cmp1_attest_date="08/08/08"
cmp1_attest_cust="ATST_CUST1"

# COMPONENT 2 BUILD PARAMETERS
cmp2_design="."
cmp2_output_name="cmp2"
cmp2_output_dir="build"
cmp2_component_id="0x11111125"
cmp2_boot_message="Component 2 Boot!"
cmp2_attest_loc="ATST_LOC2"
cmp2_attest_date="09/09/09"
cmp2_attest_cust="ATST_CUST2"

# COMPONENT 3 BUILD PARAMETERS
cmp3_design="."
cmp3_output_name="cmp3"
cmp3_output_dir="build"
cmp3_component_id="0x11111126"
cmp3_boot_message="Component 3 Boot!"
cmp3_attest_loc="ATST_LOC3"
cmp3_attest_date="10/10/10"
cmp3_attest_cust="ATST_CUST3"

if [ -z $(echo $IN_NIX_SHELL) ]; then
    echo "Entering nix-shell, please run again once inside"
    nix-shell
fi

if [ $1 = "depl" ]; then

    poetry run ectf_build_depl -d .

elif [ $1 = "ap" ]; then

    # Build AP
    poetry run ectf_build_ap \
    -d "$ap_design" \
    -on "$ap_output_name" \
    --p "$ap_pin" \
    -c "$ap_component_cnt" \
    -ids "$ap_component_ids" \
    -b "$ap_boot_message" \
    -t "$ap_token" \
    -od "$ap_output_dir"

elif [ $1 = "cmp1" ]; then

    poetry run ectf_build_comp \
    -d "$cmp1_design" \
    -on "$cmp1_output_name" \
    -od "$cmp1_output_dir" \
    -id "$cmp1_component_id" \
    -b "$cmp1_boot_message" \
    -al "$cmp1_attest_loc" \
    -ad "$cmp1_attest_date" \
    -ac "$cmp1_attest_cust"

elif [ $1 = "cmp2" ]; then

    poetry run ectf_build_comp \
    -d "$cmp2_design" \
    -on "$cmp2_output_name" \
    -od "$cmp2_output_dir" \
    -id "$cmp2_component_id" \
    -b "$cmp2_boot_message" \
    -al "$cmp2_attest_loc" \
    -ad "$cmp2_attest_date" \
    -ac "$cmp2_attest_cust"

elif [ $1 = "cmp3" ]; then

    poetry run ectf_build_comp \
    -d "$cmp3_design" \
    -on "$cmp3_output_name" \
    -od "$cmp3_output_dir" \
    -id "$cmp3_component_id" \
    -b "$cmp3_boot_message" \
    -al "$cmp3_attest_loc" \
    -ad "$cmp3_attest_date" \
    -ac "$cmp3_attest_cust"


# Add USB Serial to update
elif [ $1 = "uap" ]; then

    poetry run ectf_update \
    --infile "$ap_output_dir/$ap_output_name.img" \
    --port "/dev/$2" 


elif [ $1 = "ucmp1" ]; then

    poetry run ectf_update \
    --infile "$cmp1_output_dir/$cmp1_output_name.img" \
    --port "/dev/$2" 

elif [ $1 = "ucmp2" ]; then

    poetry run ectf_update \
    --infile "$cmp2_output_dir/$cmp2_output_name.img" \
    --port "/dev/$2" 

elif [ $1 = "ucmp3" ]; then

    poetry run ectf_update \
    --infile "$cmp3_output_dir/$cmp3_output_name.img" \
    --port "/dev/$2" 

elif [ $1 = "uall" ]; then

    poetry run ectf_update \
    --infile "$ap_output_dir/$ap_output_name.img" \
    --port "/dev/$2" 

    poetry run ectf_update \
    --infile "$cmp1_output_dir/$cmp1_output_name.img" \
    --port "/dev/$3" 

    poetry run ectf_update \
    --infile "$cmp2_output_dir/$cmp2_output_name.img" \
    --port "/dev/$4" 

    poetry run ectf_update \
    --infile "$cmp3_output_dir/$cmp3_output_name.img" \
    --port "/dev/$5" 



elif [ $1 = "all" ]; then

    poetry run ectf_build_depl -d .

    # Build AP
    poetry run ectf_build_ap \
    -d "$ap_design" \
    -on "$ap_output_name" \
    --p "$ap_pin" \
    -c "$ap_component_cnt" \
    -ids "$ap_component_ids" \
    -b "$ap_boot_message" \
    -t "$ap_token" \
    -od "$ap_output_dir"

    poetry run ectf_build_comp \
    -d "$cmp1_design" \
    -on "$cmp1_output_name" \
    -od "$cmp1_output_dir" \
    -id "$cmp1_component_id" \
    -b "$cmp1_boot_message" \
    -al "$cmp1_attest_loc" \
    -ad "$cmp1_attest_date" \
    -ac "$cmp1_attest_cust"

    poetry run ectf_build_comp \
    -d "$cmp2_design" \
    -on "$cmp2_output_name" \
    -od "$cmp2_output_dir" \
    -id "$cmp2_component_id" \
    -b "$cmp2_boot_message" \
    -al "$cmp2_attest_loc" \
    -ad "$cmp2_attest_date" \
    -ac "$cmp2_attest_cust"

    poetry run ectf_build_comp \
    -d "$cmp3_design" \
    -on "$cmp3_output_name" \
    -od "$cmp3_output_dir" \
    -id "$cmp3_component_id" \
    -b "$cmp3_boot_message" \
    -al "$cmp3_attest_loc" \
    -ad "$cmp3_attest_date" \
    -ac "$cmp3_attest_cust"

    # Add USB Serial to update

    if [ -n "$2" ]; then

        poetry run ectf_update \
        --infile "$ap_output_dir/$ap_output_name.img" \
        --port "/dev/$2" 

    fi

    if [ -n "$3" ]; then

        poetry run ectf_update \
        --infile "$cmp1_output_dir/$cmp1_output_name.img" \
        --port "/dev/$3" 

    fi

    if [ -n "$4" ]; then

        poetry run ectf_update \
        --infile "$cmp2_output_dir/$cmp2_output_name.img" \
        --port "/dev/$4" 

    fi

    if [ -n "$5" ]; then
        poetry run ectf_update \
        --infile "$cmp3_output_dir/$cmp3_output_name.img" \
        --port "/dev/$5" 
    fi

elif [ $1 = "openocd" ]; then
    if [[ $(pidof -x openocd) ]]; then
        echo "Killing all openocd instances"
        pkill openocd
    else 
        openocd -f debug/device_ap.cfg > /dev/null 2>&1 & 
        openocd -f debug/device_cmp1.cfg > /dev/null 2>&1 & 
        openocd -f debug/device_cmp2.cfg > /dev/null 2>&1 & 
    fi

elif [ $1 = "list" ]; then

    poetry run ectf_list \
    -a "/dev/$2" 

elif [ $1 = "boot" ]; then

    poetry run ectf_boot \
    -a "/dev/$2" 

elif [ $1 = "replace" ]; then

    poetry run ectf_replace \
    -a "/dev/$2" \
    -t "0123456789abcdef" \
    -i "$3" \
    -o "$4" 

elif [ $1 = "attest" ]; then

    poetry run ectf_attestation \
    -a "/dev/$2" \
    -p "123456" \
    -c "$3" 

else 

    echo "$1 is not a valid parameter"
fi