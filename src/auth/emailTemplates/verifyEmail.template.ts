export function verifyEmail(redirectTo: string) {
  return `
  <!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Document</title>
  </head>
  <style>
    :root {
      --blue: rgb(0, 85, 255);
      --black: rgb(50, 50, 50);
    }

    html {
      font-family: Arial, Helvetica, sans-serif;
      color: var(--black);
    }

    button {
      border-radius: 3px;
      padding: 20px;
      background-color: var(--blue);
      border: none;
      color: white;
    }

    h1 {
      color: var(--blue);
      font-size: 2.5rem;
    }

    main {
      min-height: 60vh;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      padding: 40px;
    }
  </style>
  <body>
    <main>
      <section>
        <h1>Findeet</h1>
        <h3>Email Verification</h3>
        <hr />
        <h4></h4>
        <p>Congratulations, you account is being created with Findeet</p>
      </section>

      <section>
        <p>
          Follow the link below to verify your email and complete registration.
        </p>
        <a href="${redirectTo}">
        <button>Click Here</button>
        </a>
      </section>
    </main>
  </body>
</html>

  `;
}
