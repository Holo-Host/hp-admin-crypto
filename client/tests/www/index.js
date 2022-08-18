import { HpAdminKeypair } from "@holo-host/hp-admin-keypair";

const HC_PUBLIC_KEY = "5m5srup6m3b2iilrsqmxu6ydp8p8cr0rdbh4wamupk3s4sxqr5";
const EMAIL = "pj@abba.pl";
const PASSWORD = "abbaabba";

let kp = new HpAdminKeypair(HC_PUBLIC_KEY, EMAIL, PASSWORD);

const payload = "string to sign"

console.log(kp.sign(payload));
