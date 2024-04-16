#!/bin/bash
start_time=$(date +%s)
echo -e "\n"
printf '\e[93;1m.................................................................................................................................................................\e[0m\n'
printf '\033[93;1m█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████\033[0m'
echo -e "\n"
c_d() {
    local secs=$1
    while [ $secs -ge 0 ]; do
        echo -ne "Boards ready in $secs seconds \r"
        sleep 1
        ((secs--))
    done
}
echo -e "\n"
printf '\e[93;1m.................................................................................................................................................................\e[0m\n'
printf '\033[93;1m█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████\033[0m'
echo -e "\n"
echo -e "\n"
printf '\e[93;1m.................................................................................................................................................................\e[0m\n'
printf '\033[93;1m█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████\033[0m'
commands=(
    "ectf_build_depl -d ."
    "ectf_build_ap -d . -on ap -od build -p 'T7hU&3' -t G978bw47Jcc5f -c 2 -ids '0x12344321, 0x43211234' -b 'Ap boot ready'"
    "ectf_build_comp -d . -on comp1 -od build -id 0x12344321 -b 'Component 1 Boot' -al co -ad 03/02/2024 -ac UCCS"
    "ectf_build_comp -d . -on comp2 -od build -id 0x43211234 -b 'Component 2 Boot' -al co -ad 03/02/2024 -ac UCCS"
    "diskutil unmount /dev/disk2"
    "diskutil unmount /dev/disk3"
    "diskutil unmount /dev/disk4"
    "echo "Quangeek22@"|sudo -S cp /Users/ilu/Downloads/insecure\ \(1\).bin /dev/disk2"
    "echo "Quangeek22@"|sudo -S cp /Users/ilu/Downloads/insecure\ \(1\).bin /dev/disk3"
    "echo "Quangeek22@"|sudo -S cp /Users/ilu/Downloads/insecure\ \(1\).bin /dev/disk4"
    "c_d"
    "ectf_update --infile build/ap.img --port /dev/tty.usbmodem141202"
    "ectf_update --infile build/comp1.img --port /dev/tty.usbmodem141302"
    "ectf_update --infile build/comp2.img --port /dev/tty.usbmodem141402"
    "ectf_list -a /dev/tty.usbmodem141202"
    "ectf_attestation -a /dev/tty.usbmodem141202 -p 'T7hU&3' -c 0x12344321"
    "ectf_attestation -a /dev/tty.usbmodem141202 -p 5211313 -c 0x43211234"
    "ectf_attestation -a /dev/tty.usbmodem141202 -p 'T7hU&3' -c 0x43211234"
    "ectf_replace -a /dev/tty.usbmodem141202 -t G978bw47Jcc5f -i 0x33445522 -o 0x12344321"
    "ectf_replace -a /dev/tty.usbmodem141202 -t G978bw47Jcc5fggg -i 0x33445522 -o 0x12344321"
    "ectf_replace -a /dev/tty.usbmodem141202 -t 'G9@%^^#23;78bw47Jcc5f' -i 0x12344321 -o 33445522"
    "ectf_replace -a /dev/tty.usbmodem141202 -t 'G9@%^^#23;78bw47Jcc5f' -i 0x12344321 -o 33445522"
    "ectf_replace -a /dev/tty.usbmodem141202 -t 'G9@%^^#23;78bw47Jcc5f' -i 0x12344321 -o 33445522"
    "ectf_replace -a /dev/tty.usbmodem141202 -t 'G9@%^^#23;78bw47Jcc5f' -i 0x12344321 -o 33445522"
    "ectf_replace -a /dev/tty.usbmodem141202 -t 'G9@%^^#23;78bw47Jcc5f' -i 0x12344321 -o 33445522"
    "ectf_replace -a /dev/tty.usbmodem141202 -t 'G9@%^^#23;78bw47Jcc5f' -i 0x12344321 -o 33445522"
    "ectf_replace -a /dev/tty.usbmodem141202 -t 'G9@%^^#23;78bw47Jcc5f' -i 0x12344321 -o 33445522"
    "ectf_replace -a /dev/tty.usbmodem141202 -t G978bw47Jcc5f -i 0x12344321 -o 0x33445522"
    "ectf_replace -a /dev/tty.usbmodem141202 -t 'G9@%^^#23;78bw47Jcsadjkghsdfghkjsasfgdafgfsdfawergsdafhgsefdsafddhgc5f' -i 0x12344321 -o 33445522"
)
# width=$(tput cols)


for cmd in "${commands[@]}"; do
    cmd_name=$(echo "$cmd" | cut -d ' ' -f 1)
    printf '\e[93;1m.................................................................................................................................................................\e[0m\n'
    echo "Executing : $cmd_name"
    printf '\e[93;1m.................................................................................................................................................................\e[0m\n'
    printf '\033[93;1m█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████\033[0m'
    printf '\e[93;1m.................................................................................................................................................................\e[0m\n'
    echo "Executing command: $cmd"
    printf '\e[93;1m.................................................................................................................................................................\e[0m\n'
    # say --quality 127 -r 130 -v Whisper "Now, Executing $cmd_name"
    if [[ "$cmd" == *"c_d"* ]]; then
        c_d 23
        echo -e "Boards ready for Opeartion"
    fi
    eval "$cmd"
    printf '\e[93;1m.................................................................................................................................................................\e[0m\n'
    printf '\e[93;1m.................................................................................................................................................................\e[0m\n'
    # say --quality 127 -r 130 -v Whisper "Command $cmd_name execution, complete."
    printf '\033[93;1m█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████\033[0m'
    echo -e "\n"
    printf '\033[93;1m█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████\033[0m'
    echo -e "\n"
    printf '\033[93;1m█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████\033[0m'
    echo -e "\n"
    sleep 2
done
end_time=$(date +%s)
total_minutes=$(($((end_time - start_time)) / 60))
echo "Total time taken: $total_minutes minutes"
say --quality 127 -r 130 -v Whisper "All execution complete, output ready for evaluation."
