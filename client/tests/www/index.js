import { HpAdminKeypair } from "@holo-host/hp-admin-keypair";

// const HpAdminKeypair = require('@holo-host/hp-admin-keypair').HpAdminKeypair

const HC_PUBLIC_KEY = "5m5srup6m3b2iilrsqmxu6ydp8p8cr0rdbh4wamupk3s4sxqr5";
const EMAIL = "pj@abba.pl";
const PASSWORD = "abbaabba";

let kp = new HpAdminKeypair(HC_PUBLIC_KEY, EMAIL, PASSWORD);

const payload = {
    method: "get",
    request: "/api/v1/config",
    body: ""
}

console.log(kp.sign(payload));
