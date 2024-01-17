import { HpAdminKeypair } from "@holo-host/hp-admin-keypair";

const HC_PUBLIC_KEY = "13lthbbhje56kimmeadqzhqw2ok47ddd7gdw5g24fnu8n4qx63";
const EMAIL = "Bartgrande@ziggo.nl";
const PASSWORD = "BartGroot";

let kp = new HpAdminKeypair(HC_PUBLIC_KEY, EMAIL, PASSWORD);

const payload = "eH_DKOnv96FJlYTvsOiPKKSksHWbA7inbh0OebnLoRFKzQn4x0K9P9QMGfW7hhUcW3jAo1wTPh5hCQ9OSSQBFVwVWeBjeE5L2kgY1Xb1FZxfuI1yqC5Krmp-Ab3HEEiygWQbp4QrujflV3MmTazp94RNgc_FJkDwokWaQ0IP2CU"

console.log(kp.sign(payload));
