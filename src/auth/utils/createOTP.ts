export function createOTP(): string {
  let randomNumberString = '';
  for (let i = 0; i < 6; i++) {
    randomNumberString += Math.round(Math.random() * 6);
  }
  return randomNumberString;
}
