/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2026 OSSTech Corporation
 */

import React from 'react';
import { HashRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Install } from './Pages/Install';
import DefaultSetting from './Pages/DefaultSetting';
import CustomSetting from './Pages/CustomSetting';
import Upgrade from './Pages/Upgrade'
import i18n from "i18next";
import LanguageDetector from 'i18next-browser-languagedetector';
import { initReactI18next } from "react-i18next";
import translationEN from "../resources/locales/en/translation.json"
import translationJA from "../resources/locales/ja/translation.json"
import translationDE from "../resources/locales/de/translation.json"
import translationES from "../resources/locales/es/translation.json"
import translationFR from "../resources/locales/fr/translation.json"
import translationKO from "../resources/locales/ko/translation.json"
import translationZH from "../resources/locales/zh/translation.json"
import translationZHTW from "../resources/locales/zh_TW/translation.json"
import { createTheme, ThemeProvider } from '@mui/material';

const resources = {
    en: {
        translation: translationEN
    },
    ja: {
        translation: translationJA
    },
    de: {
        translation: translationDE
    },
    es: {
        translation: translationES
    },
    fr: {
        translation: translationFR
    },
    ko: {
        translation: translationKO
    },
    zh: {
        translation: translationZH
    },
    zh_TW: {
        translation: translationZHTW
    }
}
const detectionOption = {
    order: ['querystring', 'navigator',]
}
i18n
    .use(initReactI18next)
    .use(LanguageDetector)
    .init({
        resources,
        fallbackLng: "en",
        detection: detectionOption,
        showSupportNotice: false,
        interpolation: {
            escapeValue: false
        }
    });

const theme = createTheme({
    palette: {
        primary: {
            main: "#004d6e"
        },
        secondary: {
            main: "#0094d4"
        }
    }
});

const App = () => {
    return (
        <>
            <ThemeProvider theme={theme}>
                <Router hashType="noslash">
                    <Routes>
                        <Route path="/" element={<Install />} />
                        <Route path="/default" element={<DefaultSetting />} />
                        <Route path="/custom" element={<CustomSetting />} />
                        <Route path="/upgrade" element={<Upgrade />} />
                        <Route path="*" element={<Navigate to="/" replace />} />
                    </Routes>
                </Router>
            </ThemeProvider>
        </>
    );
};

export default App;
