﻿using System;

namespace Cryptography.Tests
{
    public static class CryptographyTestsData
    {
        public static string[] plainText = new string[] {@"
                Oddzielili cię, syneczku, od snów, co jak motyl drżą,
                haftowali ci, syneczku, smutne oczy rudą krwią,
                malowali krajobrazy w żółte ściegi pożóg
                wyszywali wisielcami drzew płynące morze.

                    Wyuczyli cię, syneczku, ziemi twej na pamięć,
                    gdyś jej ścieżki powycinał żelaznymi łzami.
                    Odchowali cię w ciemności, odkarmili bochnem trwóg,
                    przemierzyłeś po omacku najwstydliwsze z ludzkich dróg.

                I wyszedłeś jasny synku, z czarną bronią w noc,
                i poczułeś, jak się jeży w dźwięku minut - zło.
                Zanim padłeś, jeszcze ziemię przeżegnałeś ręką.
                Czy to była kula, synku, czy to serce pękło?",
                "aAąĄźŹćŃ",
                @"!@#$%^&*()_+}{|:"":?><><||\\,./\;'][]-=90-8767435324123```~~~~~/*-/+9"};
        
        public static readonly Random _rand = new Random();
    }
}
