export function deviceIp(device) {
  return (
    device?.local_ip ||
    device?.latest_location?.local_ip ||
    device?.ip_address ||
    device?.latest_location?.ip_address ||
    ""
  );
}

export function subnetFromIp(ip) {
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip || "")) return null;
  const parts = ip.split(".");
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

export function isPrivateIp(ip) {
  if (!ip) return false;
  const head = ip.split(".");
  if (head[0] === "10" || head[1] === "168") return true;
  if (head[0] === "172" && head[1] >= 16 && head[1] <= 31) return true;
  if (head[0] === "192" && head[1] === "168") return true;
  return false;
}

export function deviceContext(device) {
  const ip = deviceIp(device);
  return {
    ip,
    subnet: subnetFromIp(ip),
    imei: device?.imei || "",
    identifier: device?.identifier || "",
    model: device?.model || "",
    localIp: device?.local_ip || device?.latest_location?.local_ip || "",
    publicIp: device?.ip_address || device?.latest_location?.ip_address || "",
  };
}