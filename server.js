"use strict";

/*
======================================================================
                         ZYNX WEB BACKEND
======================================================================

 ZYNX Discord Automation Platform
 Backend Core

 Version:
    5.0.0

 Runtime:
    Node.js 20+

 Framework:
    Express 5

 ----------------------------------------------------------------------

 ANA SİSTEMLER

    01. Environment
    02. Application configuration
    03. ZYNX bot configuration
    04. Plans
    05. Support system
    06. Analyzer
    07. Subscription system
    08. Session
    09. Security headers
    10. Rate limiting
    11. Discord OAuth2
    12. Discord user
    13. Discord owned servers
    14. Dashboard
    15. Profile
    16. Bot invite API
    17. PLUS permissions
    18. PLUS AI foundation
    19. Support assistant
    20. Analyzer API
    21. Checkout
    22. Subscription
    23. Platform status
    24. Error handling
    25. Graceful shutdown

 ----------------------------------------------------------------------

 ÖNEMLİ

 Bu backend:

    Security / Ticket / Voice / AI / Analyzer / PLUS botlarını
    çalıştırmaz.

 Bunlar ayrı bot projeleridir.

 Web tarafının görevi:

    Discord hesabı
    ↓
    kullanıcı
    ↓
    sahip olunan sunucular
    ↓
    ZYNX dashboard
    ↓
    ZYNX sistemleri

 bağlantısını sağlamaktır.

 Bot yönetim API'leri sonraki aşamada güvenli gateway üzerinden
 bağlanacaktır.

======================================================================
*/


/* ==================================================================
   01 | IMPORTS
================================================================== */

import express from "express";
import session from "express-session";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "node:crypto";


/* ==================================================================
   02 | ENV
================================================================== */

dotenv.config();


/* ==================================================================
   03 | GLOBAL HELPERS
================================================================== */

function clean(value) {

    return String(
        value ?? ""
    ).trim();
}


function originFromUrl(value) {

    const input =
        clean(
            value
        );

    if (!input) {
        return "";
    }

    try {

        return new URL(
            input
        ).origin;

    } catch {

        return input.replace(
            /\/+$/,
            ""
        );
    }
}


function normalizeFrontendUrl(value) {

    return clean(
        value
    ).replace(
        /\/+$/,
        ""
    );
}


function uuid() {

    return crypto.randomUUID();
}


function randomHex(
    bytes = 32
) {

    return crypto
        .randomBytes(
            bytes
        )
        .toString(
            "hex"
        );
}


function now() {

    return new Date();
}


function nowISO() {

    return now().toISOString();
}


function addDays(
    date,
    days
) {

    const result =
        new Date(
            date
        );

    result.setDate(
        result.getDate() +
        days
    );

    return result;
}


function addMonths(
    date,
    months
) {

    const result =
        new Date(
            date
        );

    result.setMonth(
        result.getMonth() +
        months
    );

    return result;
}


function isExpired(
    date
) {

    if (!date) {
        return false;
    }

    const timestamp =
        new Date(
            date
        ).getTime();

    if (
        Number.isNaN(
            timestamp
        )
    ) {

        return false;
    }

    return (
        timestamp <=
        Date.now()
    );
}


function safeJSON(
    value
) {

    try {

        return JSON.stringify(
            value
        );

    } catch {

        return "{}";
    }
}


function parseJSON(
    value
) {

    try {

        return JSON.parse(
            value
        );

    } catch {

        return null;
    }
}


function clamp(
    value,
    min,
    max
) {

    return Math.min(
        Math.max(
            value,
            min
        ),
        max
    );
}


function isPlainObject(
    value
) {

    return (
        value !== null &&
        typeof value === "object" &&
        !Array.isArray(
            value
        )
    );
}


/* ==================================================================
   04 | APP
================================================================== */

const app =
    express();

app.disable(
    "x-powered-by"
);


/* ==================================================================
   05 | CONFIG
================================================================== */

const CONFIG = {

    name:
        "ZYNX WEB",

    version:
        "5.0.0",

    environment:
        clean(
            process.env.NODE_ENV
        ) ||
        "development",

    port:
        Number(
            process.env.PORT ||
            3000
        ),

    frontendUrl:
        normalizeFrontendUrl(
            process.env.FRONTEND_URL
        ),

    frontendOrigin:
        originFromUrl(
            process.env.FRONTEND_URL
        ),

    discord: {

        api:
            "https://discord.com/api/v10",

        authorize:
            "https://discord.com/oauth2/authorize",

        clientId:
            clean(
                process.env.DISCORD_CLIENT_ID
            ),

        clientSecret:
            clean(
                process.env.DISCORD_CLIENT_SECRET
            ),

        redirectUri:
            clean(
                process.env.DISCORD_REDIRECT_URI
            )
    },

    session: {

        name:
            "zynx_session",

        secret:
            clean(
                process.env.SESSION_SECRET
            ),

        maxAge:
            30 *
            24 *
            60 *
            60 *
            1000,

        oauthStateAge:
            10 *
            60 *
            1000
    },

    security: {

        requestTimeout:
            12000,

        bodyLimit:
            "1mb",

        rateWindow:
            60 * 1000,

        rateLimit:
            120
    },

    analyzer: {

        launchDate:
            "2027-09-06T16:00:00+03:00",

        version:
            "1.0.0-beta"
    },

    studio: {

        name:
            "TR LIFE STUDIOS",

        role:
            "Creator & Developer of ZYNX",

        communityUrl:
            ""
    },

    ai: {

        enabled:
            clean(
                process.env.AI_ENABLED
            ) !== "false",

        provider:
            clean(
                process.env.AI_PROVIDER
            ) ||
            "internal",

        /*
            İleride gerçek AI provider buradan
            bağlanacak.

            Örneğin:

                gemini
                openai
                custom

            gibi.
        */

        apiUrl:
            clean(
                process.env.AI_API_URL
            ),

        apiKey:
            clean(
                process.env.AI_API_KEY
            ),

        model:
            clean(
                process.env.AI_MODEL
            ) ||
            "default",

        maxOutput:
            1500
    }

};


/* ==================================================================
   06 | ENV VALIDATION
================================================================== */

function validateEnvironment() {

    const required = {

        FRONTEND_URL:
            CONFIG.frontendUrl,

        DISCORD_CLIENT_ID:
            CONFIG.discord.clientId,

        DISCORD_CLIENT_SECRET:
            CONFIG.discord.clientSecret,

        DISCORD_REDIRECT_URI:
            CONFIG.discord.redirectUri,

        SESSION_SECRET:
            CONFIG.session.secret

    };


    const missing =
        Object.entries(
            required
        )
            .filter(
                ([, value]) =>
                    !value
            )
            .map(
                ([key]) =>
                    key
            );


    if (
        missing.length
    ) {

        console.error(
            "\n❌ ZYNX ENVIRONMENT ERROR\n"
        );

        for (
            const key
            of missing
        ) {

            console.error(
                `   • ${key}`
            );
        }

        console.error("");

        process.exit(
            1
        );
    }


    if (
        CONFIG.session.secret.length <
        32
    ) {

        console.error(
            "❌ SESSION_SECRET en az 32 karakter olmalıdır."
        );

        process.exit(
            1
        );
    }


    if (
        CONFIG.environment ===
        "production"
    ) {

        if (
            !CONFIG.frontendOrigin.startsWith(
                "https://"
            )
        ) {

            console.error(
                "❌ Production FRONTEND_URL HTTPS olmalıdır."
            );

            process.exit(
                1
            );
        }
    }
}


validateEnvironment();


/* ==================================================================
   07 | ZYNX BOTS
==================================================================

   SADECE:

       name
       emoji
       description
       invite

   var.

   BOT TOKEN YOK.
   BOT CLIENT ID YOK.

================================================================== */

const ZYNX_BOTS = {

    security: {

        key:
            "security",

        name:
            "ZYNX Security",

        emoji:
            "🛡️",

        description:
            "Moderasyon, güvenlik, Anti-Spam, Anti-Raid ve koruma sistemi.",

        invite:
            "https://discord.com/oauth2/authorize?client_id=1540275059149512778&permissions=8&integration_type=0&scope=bot+applications.commands"
    },


    ticket: {

        key:
            "ticket",

        name:
            "ZYNX Ticket",

        emoji:
            "🎫",

        description:
            "Profesyonel ticket, destek ve ekip yönetim sistemi.",

        invite:
            "https://discord.com/oauth2/authorize?client_id=1542534820033462382&permissions=8&integration_type=0&scope=bot+applications.commands"
    },


    voice: {

        key:
            "voice",

        name:
            "ZYNX Voice",

        emoji:
            "🎵",

        description:
            "Müzik, ses kanalları ve gelişmiş Voice sistemi.",

        invite:
            "https://discord.com/oauth2/authorize?client_id=1542535042641825835&permissions=8&integration_type=0&scope=bot+applications.commands"
    },


    ai: {

        key:
            "ai",

        name:
            "ZYNX AI",

        emoji:
            "🤖",

        description:
            "Yapay zekâ destekli soru-cevap ve Discord otomasyonu.",

        invite:
            "https://discord.com/oauth2/authorize?client_id=1542535094286295110&permissions=8&integration_type=0&scope=bot+applications.commands"
    },


    analyzer: {

        key:
            "analyzer",

        name:
            "ZYNX Analyzer",

        emoji:
            "🔍",

        description:
            "Sunucuyu analiz eder, eksikleri ve güvenlik risklerini tespit eder.",

        invite:
            "BURAYA_ANALYZER_DAVET_LINKI",

        releaseDate:
            "2027-09-06T16:00:00+03:00",

        beta:
            true
    },


    plus: {

        key:
            "plus",

        name:
            "ZYNX PLUS",

        emoji:
            "✦",

        description:
            "PLUS üyelerine özel gelişmiş AI ve otomasyon botu.",

        invite:
            "BURAYA_PLUS_BOT_DAVET_LINKI",

        beta:
            true,

        plusOnly:
            true
    }

};


/* ==================================================================
   08 | PLANS
================================================================== */

const PLANS = {

    FREE: {

        id:
            "FREE",

        name:
            "ZYNX FREE",

        price:
            0,

        currency:
            "TRY",

        period:
            "month",

        description:
            "ZYNX platformuna temel erişim.",

        features: [

            "Temel Dashboard",

            "Discord profil bağlantısı",

            "Sahibi olduğun sunucuları görüntüleme",

            "Temel komut merkezi",

            "ZYNX sistemlerine erişim"

        ]
    },


    PRO: {

        id:
            "PRO",

        name:
            "ZYNX PRO",

        price:
            149,

        currency:
            "TRY",

        period:
            "month",

        description:
            "ZYNX botlarının gelişmiş özelliklerini aç.",

        features: [

            "FREE özelliklerinin tamamı",

            "Gelişmiş Security",

            "Gelişmiş Ticket",

            "Gelişmiş Voice",

            "Gelişmiş AI",

            "Premium komutlar",

            "Gelişmiş sunucu yönetimi"

        ]
    },


    PLUS: {

        id:
            "PLUS",

        name:
            "ZYNX PLUS",

        price:
            299,

        currency:
            "TRY",

        period:
            "month",

        description:
            "AI destekli gelişmiş yönetim ve otomasyon.",

        features: [

            "PRO özelliklerinin tamamı",

            "ZYNX PLUS Bot",

            "ZYNX PLUS AI",

            "AI destekli sunucu yönetimi",

            "Otomatik analiz",

            "Akıllı öneriler",

            "Otomatik sistem hazırlığı",

            "Gelişmiş destek asistanı",

            "Analyzer gelişmiş erişimi"

        ]
    }

};


/* ==================================================================
   09 | SUPPORT SYSTEM
================================================================== */

const SUPPORT_CATEGORIES = {

    bot: {

        id:
            "bot",

        title:
            "Bot Çalışmıyor",

        description:
            "ZYNX botlarından biriyle ilgili sorun.",

        questions: [

            "Hangi ZYNX botunda sorun var?",

            "Bot sunucuda görünüyor mu?",

            "Sorun ne zaman başladı?",

            "Bot komutlara cevap veriyor mu?"

        ]
    },


    ticket: {

        id:
            "ticket",

        title:
            "Ticket Sorunu",

        description:
            "Ticket paneli veya ticket açma sorunları.",

        questions: [

            "Ticket paneli görünüyor mu?",

            "Ticket açılmaya çalışıldığında ne oluyor?",

            "Yetkili rolü yapılandırıldı mı?",

            "Ticket kanalı oluşuyor mu?"

        ]
    },


    security: {

        id:
            "security",

        title:
            "Security Sorunu",

        description:
            "Moderasyon veya güvenlik problemi.",

        questions: [

            "Hangi güvenlik sistemi çalışmıyor?",

            "Botun gerekli izinleri var mı?",

            "Sorun tüm kullanıcıları mı etkiliyor?",

            "Son yapılandırma değişikliği neydi?"

        ]
    },


    voice: {

        id:
            "voice",

        title:
            "Voice Sorunu",

        description:
            "Müzik veya ses sistemi sorunları.",

        questions: [

            "Bot ses kanalına girebiliyor mu?",

            "Müzik başlatılabiliyor mu?",

            "Botun mikrofon/ses izinleri var mı?",

            "Sorun tüm ses kanallarında mı?"

        ]
    },


    ai: {

        id:
            "ai",

        title:
            "AI Sorunu",

        description:
            "ZYNX AI veya PLUS AI problemi.",

        questions: [

            "AI cevap vermiyor mu?",

            "Cevaplar hatalı mı?",

            "Sorun hangi sunucuda?",

            "Sorun sürekli mi gerçekleşiyor?"

        ]
    },


    website: {

        id:
            "website",

        title:
            "Site Sorunu",

        description:
            "ZYNX Web paneli ile ilgili sorun.",

        questions: [

            "Hangi sayfada sorun var?",

            "Sayfa yükleniyor mu?",

            "Bir hata mesajı görüyor musunuz?",

            "Sorun ne zaman başladı?"

        ]
    },


    billing: {

        id:
            "billing",

        title:
            "Abonelik / Ödeme",

        description:
            "Plan veya abonelik problemi.",

        questions: [

            "Hangi planı kullanıyorsunuz?",

            "Abonelik aktif görünüyor mu?",

            "Ödeme adımında mı sorun oluşuyor?",

            "Bir hata kodu görüyor musunuz?"

        ]
    },


    other: {

        id:
            "other",

        title:
            "Diğer",

        description:
            "Diğer tüm sorunlar.",

        questions: [

            "Sorununuzu kısaca anlatın.",

            "Sorun hangi sistemle ilgili?",

            "Sorun hangi sunucuda?",

            "Sorun ne zaman başladı?"

        ]
    }

};


/* ==================================================================
   10 | SUBSCRIPTION STORAGE
==================================================================

   LOCAL DEVELOPMENT STORAGE.

   Production'da PostgreSQL'e taşınacak.

================================================================== */

const subscriptions =
    new Map();


const profiles =
    new Map();


const checkoutSessions =
    new Map();


const supportSessions =
    new Map();


/* ==================================================================
   11 | RATE LIMIT STORAGE
================================================================== */

const rateStore =
    new Map();


/* ==================================================================
   12 | SESSION HELPERS
================================================================== */

function saveSession(
    req
) {

    return new Promise(
        (
            resolve,
            reject
        ) => {

            req.session.save(
                error => {

                    if (
                        error
                    ) {

                        reject(
                            error
                        );

                        return;
                    }


                    resolve();
                }
            );
        }
    );
}


function regenerateSession(
    req
) {

    return new Promise(
        (
            resolve,
            reject
        ) => {

            req.session.regenerate(
                error => {

                    if (
                        error
                    ) {

                        reject(
                            error
                        );

                        return;
                    }


                    resolve();
                }
            );
        }
    );
}


function destroySession(
    req
) {

    return new Promise(
        (
            resolve,
            reject
        ) => {

            req.session.destroy(
                error => {

                    if (
                        error
                    ) {

                        reject(
                            error
                        );

                        return;
                    }


                    resolve();
                }
            );
        }
    );
}


/* ==================================================================
   13 | SUBSCRIPTION HELPERS
================================================================== */

function getSubscription(
    userId
) {

    let subscription =
        subscriptions.get(
            userId
        );


    if (
        !subscription
    ) {

        subscription = {

            userId,

            plan:
                "FREE",

            status:
                "inactive",

            startedAt:
                null,

            trialStartedAt:
                null,

            trialEndsAt:
                null,

            currentPeriodStart:
                null,

            currentPeriodEnd:
                null,

            cancelAtPeriodEnd:
                false,

            canceledAt:
                null,

            createdAt:
                nowISO(),

            updatedAt:
                nowISO()
        };


        subscriptions.set(
            userId,
            subscription
        );
    }


    return subscription;
}


function updateSubscription(
    userId,
    changes
) {

    const current =
        getSubscription(
            userId
        );


    const updated = {

        ...current,

        ...changes,

        updatedAt:
            nowISO()
    };


    subscriptions.set(
        userId,
        updated
    );


    return updated;
}


function refreshSubscription(
    userId
) {

    const current =
        getSubscription(
            userId
        );


    /*
        Trial bitti.
    */

    if (
        current.status ===
            "trialing" &&
        current.trialEndsAt &&
        isExpired(
            current.trialEndsAt
        )
    ) {

        return updateSubscription(

            userId,

            {

                plan:
                    "FREE",

                status:
                    "inactive",

                currentPeriodStart:
                    null,

                currentPeriodEnd:
                    null,

                cancelAtPeriodEnd:
                    false
            }

        );
    }


    /*
        Ücretli dönem bitti.
    */

    if (
        current.status ===
            "active" &&
        current.currentPeriodEnd &&
        isExpired(
            current.currentPeriodEnd
        )
    ) {

        return updateSubscription(

            userId,

            {

                plan:
                    "FREE",

                status:
                    "inactive",

                currentPeriodStart:
                    null,

                currentPeriodEnd:
                    null,

                cancelAtPeriodEnd:
                    false
            }

        );
    }


    return current;
}


function publicSubscription(
    subscription
) {

    return {

        plan:
            subscription.plan,

        status:
            subscription.status,

        startedAt:
            subscription.startedAt,

        trialStartedAt:
            subscription.trialStartedAt,

        trialEndsAt:
            subscription.trialEndsAt,

        currentPeriodStart:
            subscription.currentPeriodStart,

        currentPeriodEnd:
            subscription.currentPeriodEnd,

        cancelAtPeriodEnd:
            Boolean(
                subscription.cancelAtPeriodEnd
            ),

        canceledAt:
            subscription.canceledAt
    };
}


function isPlusMember(
    userId
) {

    const subscription =
        refreshSubscription(
            userId
        );


    return (
        subscription.plan ===
            "PLUS" &&

        (
            subscription.status ===
                "active" ||

            subscription.status ===
                "trialing"
        )
    );
}


function isPremiumMember(
    userId
) {

    const subscription =
        refreshSubscription(
            userId
        );


    return (

        (
            subscription.plan ===
                "PRO" ||

            subscription.plan ===
                "PLUS"
        ) &&

        (
            subscription.status ===
                "active" ||

            subscription.status ===
                "trialing"
        )

    );
}


/* ==================================================================
   14 | PROFILE HELPERS
================================================================== */

function getProfile(
    userId
) {

    let profile =
        profiles.get(
            userId
        );


    if (
        !profile
    ) {

        profile = {

            userId,

            displayName:
                null,

            createdAt:
                nowISO(),

            updatedAt:
                nowISO()
        };


        profiles.set(
            userId,
            profile
        );
    }


    return profile;
}


/* ==================================================================
   15 | BOT PUBLIC DATA
================================================================== */

function getPublicBots() {

    return Object
        .values(
            ZYNX_BOTS
        )
        .map(
            bot => {

                const publicBot = {

                    key:
                        bot.key,

                    name:
                        bot.name,

                    emoji:
                        bot.emoji,

                    description:
                        bot.description,

                    invite:
                        safeInvite(
                            bot.invite
                        ),

                    configured:
                        Boolean(
                            safeInvite(
                                bot.invite
                            )
                        )
                };


                if (
                    bot.beta
                ) {

                    publicBot.beta =
                        true;
                }


                if (
                    bot.plusOnly
                ) {

                    publicBot.plusOnly =
                        true;
                }


                if (
                    bot.releaseDate
                ) {

                    publicBot.releaseDate =
                        bot.releaseDate;
                }


                return publicBot;
            }
        );
}


function safeInvite(
    value
) {

    const input =
        clean(
            value
        );


    if (
        !input ||
        input.startsWith(
            "BURAYA_"
        )
    ) {

        return "";
    }


    try {

        const url =
            new URL(
                input
            );


        if (
            url.protocol !==
                "https:" &&
            url.protocol !==
                "http:"
        ) {

            return "";
        }


        return url.href;

    } catch {

        return "";
    }
}


/* ==================================================================
   16 | DISCORD PERMISSION HELPERS
================================================================== */

const DISCORD_PERMISSION = {

    ADMINISTRATOR:
        0x00000008n,

    MANAGE_GUILD:
        0x00000020n
};


function hasPermission(
    permissionString,
    required
) {

    try {

        const permissions =
            BigInt(
                permissionString ||
                "0"
            );


        return (
            permissions &
            required
        ) !==
        0n;

    } catch {

        return false;
    }
}


/* ==================================================================
   17 | MIDDLEWARE
================================================================== */

app.use(
    cors({

        origin:
            CONFIG.frontendOrigin,

        credentials:
            true,

        methods: [

            "GET",
            "POST",
            "PATCH",
            "DELETE",
            "OPTIONS"

        ],

        allowedHeaders: [

            "Accept",
            "Content-Type",
            "X-Requested-With"

        ]
    })
);


app.use(
    express.json({

        limit:
            CONFIG.security.bodyLimit
    })
);


app.use(
    express.urlencoded({

        extended:
            true,

        limit:
            CONFIG.security.bodyLimit
    })
);


/* ==================================================================
   18 | REQUEST ID
================================================================== */

app.use(
    (
        req,
        res,
        next
    ) => {

        req.requestId =
            uuid();


        res.setHeader(
            "X-Request-ID",
            req.requestId
        );


        next();
    }
);


/* ==================================================================
   19 | SECURITY HEADERS
================================================================== */

app.use(
    (
        req,
        res,
        next
    ) => {

        res.setHeader(
            "X-Content-Type-Options",
            "nosniff"
        );


        res.setHeader(
            "X-Frame-Options",
            "DENY"
        );


        res.setHeader(
            "Referrer-Policy",
            "strict-origin-when-cross-origin"
        );


        res.setHeader(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()"
        );


        res.setHeader(
            "Cross-Origin-Resource-Policy",
            "cross-origin"
        );


        next();
    }
);


/* ==================================================================
   20 | BASIC RATE LIMIT
================================================================== */

app.use(
    (
        req,
        res,
        next
    ) => {

        const forwarded =
            req.headers[
                "x-forwarded-for"
            ];


        const ip =
            String(
                forwarded ||
                req.socket?.remoteAddress ||
                "unknown"
            )
                .split(",")[0]
                .trim();


        const current =
            rateStore.get(
                ip
            );


        const timestamp =
            Date.now();


        if (
            !current ||
            (
                timestamp -
                current.startedAt
            ) >
            CONFIG.security.rateWindow
        ) {

            rateStore.set(

                ip,

                {

                    startedAt:
                        timestamp,

                    count:
                        1

                }

            );


            next();

            return;
        }


        current.count++;


        if (
            current.count >
            CONFIG.security.rateLimit
        ) {

            res.setHeader(
                "Retry-After",
                "60"
            );


            return res
                .status(429)
                .json({

                    success:
                        false,

                    code:
                        "RATE_LIMIT",

                    message:
                        "Çok fazla istek gönderildi. Lütfen biraz sonra tekrar deneyin.",

                    requestId:
                        req.requestId
                });
        }


        next();
    }
);


/* ==================================================================
   21 | SESSION
================================================================== */

app.use(
    session({

        name:
            CONFIG.session.name,

        secret:
            CONFIG.session.secret,

        resave:
            false,

        saveUninitialized:
            false,

        rolling:
            true,

        cookie: {

            httpOnly:
                true,

            secure:
                CONFIG.environment ===
                "production",

            sameSite:
                CONFIG.environment ===
                "production"
                    ? "none"
                    : "lax",

            maxAge:
                CONFIG.session.maxAge
        }
    })
);


/* ==================================================================
   22 | AUTH MIDDLEWARE
================================================================== */

function requireAuth(
    req,
    res,
    next
) {

    if (
        !req.session?.user
    ) {

        return res
            .status(401)
            .json({

                success:
                    false,

                authenticated:
                    false,

                code:
                    "AUTH_REQUIRED",

                message:
                    "Bu işlem için Discord hesabınızla giriş yapmalısınız.",

                requestId:
                    req.requestId
            });
    }


    next();
}


/* ==================================================================
   23 | PLUS MIDDLEWARE
================================================================== */

function requirePlus(
    req,
    res,
    next
) {

    if (
        !req.session?.user
    ) {

        return res
            .status(401)
            .json({

                success:
                    false,

                code:
                    "AUTH_REQUIRED",

                message:
                    "Giriş yapmalısınız.",

                requestId:
                    req.requestId
            });
    }


    if (
        !isPlusMember(
            req.session.user.id
        )
    ) {

        return res
            .status(403)
            .json({

                success:
                    false,

                code:
                    "PLUS_REQUIRED",

                requiredPlan:
                    "PLUS",

                currentPlan:
                    refreshSubscription(
                        req.session.user.id
                    ).plan,

                message:
                    "Bu özellik yalnızca ZYNX PLUS üyelerine açıktır.",

                requestId:
                    req.requestId
            });
    }


    next();
}


/* ==================================================================
   24 | DISCORD REQUEST
================================================================== */

async function discordFetch(
    url,
    options = {},
    retry = 0
) {

    const controller =
        new AbortController();


    const timeout =
        setTimeout(
            () =>
                controller.abort(),
            CONFIG.security.requestTimeout
        );


    try {

        const response =
            await fetch(
                url,
                {

                    ...options,

                    signal:
                        controller.signal
                }
            );


        /*
            Discord rate limit.
        */

        if (
            response.status ===
                429 &&
            retry < 2
        ) {

            const retryAfter =
                Number(
                    response.headers.get(
                        "retry-after"
                    )
                );


            const delay =
                Number.isFinite(
                    retryAfter
                )
                    ? Math.min(
                        retryAfter * 1000,
                        10000
                    )
                    : 1500;


            await new Promise(
                resolve =>
                    setTimeout(
                        resolve,
                        delay
                    )
            );


            return discordFetch(
                url,
                options,
                retry + 1
            );
        }


        const raw =
            await response.text();


        const data =
            raw
                ? parseJSON(
                    raw
                ) ??
                  raw

                : null;


        if (
            !response.ok
        ) {

            const error =
                new Error(
                    `Discord API ${response.status}`
                );


            error.status =
                response.status;


            error.data =
                data;


            error.retryAfter =
                response.headers.get(
                    "retry-after"
                );


            throw error;
        }


        return data;

    } catch (error) {

        if (
            error?.name ===
            "AbortError"
        ) {

            const timeoutError =
                new Error(
                    "Discord API isteği zaman aşımına uğradı."
                );


            timeoutError.code =
                "DISCORD_TIMEOUT";


            throw timeoutError;
        }


        throw error;

    } finally {

        clearTimeout(
            timeout
        );
    }
}


/* ==================================================================
   25 | DISCORD TOKEN EXCHANGE
================================================================== */

async function exchangeDiscordCode(
    code
) {

    const body =
        new URLSearchParams({

            grant_type:
                "authorization_code",

            code,

            redirect_uri:
                CONFIG.discord.redirectUri

        });


    const authorization =
        Buffer
            .from(
                `${CONFIG.discord.clientId}:${CONFIG.discord.clientSecret}`
            )
            .toString(
                "base64"
            );


    return discordFetch(

        `${CONFIG.discord.api}/oauth2/token`,

        {

            method:
                "POST",

            headers: {

                "Content-Type":
                    "application/x-www-form-urlencoded",

                Authorization:
                    `Basic ${authorization}`
            },

            body:
                body.toString()
        }

    );
}


/* ==================================================================
   26 | TOKEN REFRESH
================================================================== */

async function refreshDiscordToken(
    req
) {

    const oauth =
        req.session?.discordOAuth;


    if (
        !oauth?.refreshToken
    ) {

        return null;
    }


    try {

        const body =
            new URLSearchParams({

                grant_type:
                    "refresh_token",

                refresh_token:
                    oauth.refreshToken
            });


        const authorization =
            Buffer
                .from(
                    `${CONFIG.discord.clientId}:${CONFIG.discord.clientSecret}`
                )
                .toString(
                    "base64"
                );


        const token =
            await discordFetch(

                `${CONFIG.discord.api}/oauth2/token`,

                {

                    method:
                        "POST",

                    headers: {

                        "Content-Type":
                            "application/x-www-form-urlencoded",

                        Authorization:
                            `Basic ${authorization}`
                    },

                    body:
                        body.toString()
                }

            );


        req.session.discordOAuth = {

            accessToken:
                token.access_token,

            refreshToken:
                token.refresh_token ||
                oauth.refreshToken,

            tokenType:
                token.token_type ||
                "Bearer",

            expiresIn:
                Number(
                    token.expires_in ||
                    604800
                ),

            expiresAt:
                Date.now() +
                (
                    Number(
                        token.expires_in ||
                        604800
                    ) *
                    1000
                )

        };


        await saveSession(
            req
        );


        return req.session.discordOAuth;

    } catch (error) {

        console.error(
            "[ZYNX] Discord token refresh failed:",
            error?.data ||
            error
        );


        return null;
    }
}


/* ==================================================================
   27 | VALID OAUTH
================================================================== */

async function getDiscordOAuth(
    req
) {

    let oauth =
        req.session?.discordOAuth;


    if (
        !oauth?.accessToken
    ) {

        return null;
    }


    const expiresAt =
        Number(
            oauth.expiresAt ||
            0
        );


    const shouldRefresh =
        !expiresAt ||
        (
            expiresAt -
            Date.now()
        ) <
        5 * 60 * 1000;


    if (
        shouldRefresh &&
        oauth.refreshToken
    ) {

        const refreshed =
            await refreshDiscordToken(
                req
            );


        if (
            refreshed
        ) {

            oauth =
                refreshed;
        }
    }


    return oauth;
}


/* ==================================================================
   28 | DISCORD USER REQUEST
================================================================== */

async function discordUserRequest(
    req,
    endpoint
) {

    let oauth =
        await getDiscordOAuth(
            req
        );


    if (
        !oauth
    ) {

        const error =
            new Error(
                "Discord OAuth session bulunamadı."
            );


        error.status =
            401;


        throw error;
    }


    const makeRequest =
        token =>
            discordFetch(

                `${CONFIG.discord.api}${endpoint}`,

                {

                    method:
                        "GET",

                    headers: {

                        Authorization:
                            `${token.tokenType || "Bearer"} ${token.accessToken}`,

                        Accept:
                            "application/json"

                    }

                }

            );


    try {

        return await makeRequest(
            oauth
        );

    } catch (error) {

        if (
            error.status ===
                401 &&
            oauth.refreshToken
        ) {

            const refreshed =
                await refreshDiscordToken(
                    req
                );


            if (
                refreshed
            ) {

                return makeRequest(
                    refreshed
                );
            }
        }


        throw error;
    }
}


/* ==================================================================
   29 | PUBLIC HEALTH
================================================================== */

app.get(
    "/api/health",
    (
        req,
        res
    ) => {

        res.json({

            success:
                true,

            service:
                CONFIG.name,

            version:
                CONFIG.version,

            environment:
                CONFIG.environment,

            status:
                "online",

            timestamp:
                nowISO(),

            requestId:
                req.requestId

        });
    }
);


/* ==================================================================
   30 | PUBLIC CONFIG
================================================================== */

app.get(
    "/api/config",
    (
        req,
        res
    ) => {

        res.json({

            success:
                true,

            app: {

                name:
                    CONFIG.name,

                version:
                    CONFIG.version
            },

            studio:
                CONFIG.studio,

            analyzer: {

                version:
                    CONFIG.analyzer.version,

                releaseDate:
                    CONFIG.analyzer.launchDate,

                beta:
                    true
            },

            bots:
                getPublicBots(),

            plans:
                PLANS,

            requestId:
                req.requestId
        });
    }
);


/* ==================================================================
   31 | DISCORD LOGIN
================================================================== */

app.get(
    "/auth/discord",
    async (
        req,
        res
    ) => {

        try {

            const state =
                randomHex(
                    32
                );


            req.session.oauthState = {

                value:
                    state,

                createdAt:
                    Date.now()
            };


            await saveSession(
                req
            );


            const params =
                new URLSearchParams({

                    client_id:
                        CONFIG.discord.clientId,

                    response_type:
                        "code",

                    redirect_uri:
                        CONFIG.discord.redirectUri,

                    scope:
                        "identify guilds",

                    state

                });


            const url =
                `${CONFIG.discord.authorize}?${params.toString()}`;


            return res.redirect(
                url
            );

        } catch (error) {

            console.error(
                "[ZYNX] OAuth start:",
                error
            );


            return res
                .status(500)
                .send(
                    "Discord giriş sistemi başlatılamadı."
                );
        }
    }
);


/* ==================================================================
   32 | DISCORD CALLBACK
================================================================== */

app.get(
    "/auth/discord/callback",
    async (
        req,
        res
    ) => {

        const code =
            clean(
                req.query.code
            );


        const state =
            clean(
                req.query.state
            );


        const error =
            clean(
                req.query.error
            );


        if (
            error
        ) {

            return res.redirect(
                `${CONFIG.frontendUrl}/?auth_error=${encodeURIComponent(error)}`
            );
        }


        if (
            !code ||
            !state
        ) {

            return res.redirect(
                `${CONFIG.frontendUrl}/?auth_error=missing_oauth_parameters`
            );
        }


        try {

            const storedState =
                req.session?.oauthState;


            if (
                !storedState?.value
            ) {

                return res.redirect(
                    `${CONFIG.frontendUrl}/?auth_error=session_state_missing`
                );
            }


            /*
                State expires.
            */

            if (
                Date.now() -
                    Number(
                        storedState.createdAt
                    ) >
                CONFIG.session.oauthStateAge
            ) {

                return res.redirect(
                    `${CONFIG.frontendUrl}/?auth_error=state_expired`
                );
            }


            const expected =
                Buffer.from(
                    storedState.value
                );


            const received =
                Buffer.from(
                    state
                );


            if (
                expected.length !==
                received.length
            ) {

                return res.redirect(
                    `${CONFIG.frontendUrl}/?auth_error=invalid_state`
                );
            }


            if (
                !crypto.timingSafeEqual(
                    expected,
                    received
                )
            ) {

                return res.redirect(
                    `${CONFIG.frontendUrl}/?auth_error=invalid_state`
                );
            }


            /*
                State one-time use.
            */

            req.session.oauthState =
                null;


            /*
                Exchange code.
            */

            const token =
                await exchangeDiscordCode(
                    code
                );


            if (
                !token?.access_token
            ) {

                throw new Error(
                    "Discord access token alınamadı."
                );
            }


            /*
                User.
            */

            const user =
                await discordFetch(

                    `${CONFIG.discord.api}/users/@me`,

                    {

                        method:
                            "GET",

                        headers: {

                            Authorization:
                                `${token.token_type || "Bearer"} ${token.access_token}`,

                            Accept:
                                "application/json"
                        }
                    }

                );


            if (
                !user?.id
            ) {

                throw new Error(
                    "Discord kullanıcı bilgisi alınamadı."
                );
            }


            /*
                Session regeneration.
            */

            await regenerateSession(
                req
            );


            /*
                Save user.
            */

            req.session.user = {

                id:
                    String(
                        user.id
                    ),

                username:
                    user.username,

                globalName:
                    user.global_name ||
                    user.username,

                discriminator:
                    user.discriminator ||
                    "0",

                avatar:
                    user.avatar ||
                    null,

                avatarUrl:
                    getAvatarUrl(
                        user
                    ),

                locale:
                    user.locale ||
                    null,

                connectedAt:
                    nowISO()
            };


            /*
                OAuth data remains server-side.
            */

            req.session.discordOAuth = {

                accessToken:
                    token.access_token,

                refreshToken:
                    token.refresh_token ||
                    null,

                tokenType:
                    token.token_type ||
                    "Bearer",

                expiresIn:
                    Number(
                        token.expires_in ||
                        604800
                    ),

                expiresAt:
                    Date.now() +
                    (
                        Number(
                            token.expires_in ||
                            604800
                        ) *
                        1000
                    )
            };


            /*
                Subscription.
            */

            req.session.subscription =
                refreshSubscription(
                    user.id
                );


            /*
                Profile.
            */

            getProfile(
                user.id
            );


            await saveSession(
                req
            );


            return res.redirect(
                `${CONFIG.frontendUrl}/?login=success#dashboard`
            );

        } catch (error) {

            console.error(
                "\n[ZYNX] OAuth callback error:"
            );

            console.error(
                error?.data ||
                error
            );


            return res.redirect(
                `${CONFIG.frontendUrl}/?auth_error=oauth_failed`
            );
        }
    }
);


/* ==================================================================
   33 | AUTH ME
================================================================== */

app.get(
    "/api/auth/me",
    async (
        req,
        res
    ) => {

        try {

            if (
                !req.session?.user
            ) {

                return res.json({

                    success:
                        true,

                    authenticated:
                        false,

                    user:
                        null,

                    subscription:
                        null,

                    requestId:
                        req.requestId
                });
            }


            const oauth =
                await getDiscordOAuth(
                    req
                );


            if (
                !oauth
            ) {

                return res.json({

                    success:
                        true,

                    authenticated:
                        false,

                    user:
                        null,

                    subscription:
                        null,

                    requestId:
                        req.requestId
                });
            }


            const subscription =
                refreshSubscription(
                    req.session.user.id
                );


            req.session.subscription =
                subscription;


            await saveSession(
                req
            );


            return res.json({

                success:
                    true,

                authenticated:
                    true,

                user:
                    req.session.user,

                subscription:
                    publicSubscription(
                        subscription
                    ),

                plan:
                    subscription.plan,

                isPlus:
                    isPlusMember(
                        req.session.user.id
                    ),

                requestId:
                    req.requestId
            });

        } catch (error) {

            console.error(
                "[ZYNX] AUTH ME:",
                error
            );


            return res
                .status(500)
                .json({

                    success:
                        false,

                    authenticated:
                        false,

                    message:
                        "Oturum bilgileri alınamadı.",

                    requestId:
                        req.requestId
                });
        }
    }
);


/* ==================================================================
   34 | LOGOUT
================================================================== */

app.post(
    "/api/auth/logout",
    requireAuth,
    async (
        req,
        res
    ) => {

        try {

            await destroySession(
                req
            );


            res.clearCookie(
                CONFIG.session.name
            );


            return res.json({

                success:
                    true,

                message:
                    "Başarıyla çıkış yapıldı.",

                requestId:
                    req.requestId
            });

        } catch (error) {

            console.error(
                "[ZYNX] Logout:",
                error
            );


            return res
                .status(500)
                .json({

                    success:
                        false,

                    message:
                        "Çıkış yapılamadı.",

                    requestId:
                        req.requestId
                });
        }
    }
);


/* ==================================================================
   35 | DISCORD USER
================================================================== */

app.get(
    "/api/discord/user",
    requireAuth,
    async (
        req,
        res
    ) => {

        try {

            const user =
                await discordUserRequest(
                    req,
                    "/users/@me"
                );


            req.session.user = {

                ...req.session.user,

                username:
                    user.username,

                globalName:
                    user.global_name ||
                    user.username,

                discriminator:
                    user.discriminator ||
                    "0",

                avatar:
                    user.avatar ||
                    null,

                avatarUrl:
                    getAvatarUrl(
                        user
                    ),

                locale:
                    user.locale ||
                    null
            };


            await saveSession(
                req
            );


            return res.json({

                success:
                    true,

                user:
                    req.session.user,

                requestId:
                    req.requestId
            });

        } catch (error) {

            console.error(
                "[ZYNX] Discord user:",
                error
            );


            return res
                .status(
                    error?.status ===
                    401
                        ? 401
                        : 500
                )
                .json({

                    success:
                        false,

                    message:
                        "Discord kullanıcı bilgileri alınamadı.",

                    requestId:
                        req.requestId
                });
        }
    }
);


/* ==================================================================
   36 | OWNED SERVERS
==================================================================

   SADECE owner === true.

   Kullanıcının üye olduğu ama sahibi olmadığı sunucular
   dashboard'a alınmaz.

================================================================== */

app.get(
    "/api/servers",
    requireAuth,
    async (
        req,
        res
    ) => {

        try {

            const guilds =
                await discordUserRequest(
                    req,
                    "/users/@me/guilds"
                );


            const owned =
                Array.isArray(
                    guilds
                )
                    ? guilds
                        .filter(
                            guild =>
                                Boolean(
                                    guild.owner
                                )
                        )
                        .map(
                            guild => ({

                                id:
                                    guild.id,

                                name:
                                    guild.name,

                                icon:
                                    guild.icon ||
                                    null,

                                iconUrl:
                                    getGuildIconUrl(
                                        guild
                                    ),

                                owner:
                                    true,

                                permissions:
                                    String(
                                        guild.permissions ||
                                        "0"
                                    ),

                                features:
                                    Array.isArray(
                                        guild.features
                                    )
                                        ? guild.features
                                        : [],

                                /*
                                    Bot bağlantısı henüz
                                    gateway API'ye bağlanmadığı
                                    için null.

                                    Sonraki aşamada:

                                    true / false
                                */

                                bots: {

                                    security:
                                        null,

                                    ticket:
                                        null,

                                    voice:
                                        null,

                                    ai:
                                        null,

                                    analyzer:
                                        null,

                                    plus:
                                        null
                                }

                            })
                        )
                    : [];


            owned.sort(
                (
                    a,
                    b
                ) =>
                    a.name.localeCompare(
                        b.name,
                        "tr"
                    )
            );


            return res.json({

                success:
                    true,

                count:
                    owned.length,

                servers:
                    owned,

                filter:
                    "owner_only",

                requestId:
                    req.requestId
            });

        } catch (error) {

            console.error(
                "[ZYNX] Owned servers:",
                error?.data ||
                error
            );


            return res
                .status(
                    error?.status ===
                    401
                        ? 401
                        : 500
                )
                .json({

                    success:
                        false,

                    message:
                        "Sahibi olduğunuz Discord sunucuları alınamadı.",

                    requestId:
                        req.requestId
                });
        }
    }
);


/* ==================================================================
   37 | SERVER DETAIL
================================================================== */

app.get(
    "/api/servers/:guildId",
    requireAuth,
    async (
        req,
        res
    ) => {

        try {

            const guildId =
                clean(
                    req.params.guildId
                );


            if (
                !guildId
            ) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        message:
                            "Geçersiz sunucu ID.",

                        requestId:
                            req.requestId
                    });
            }


            const guilds =
                await discordUserRequest(
                    req,
                    "/users/@me/guilds"
                );


            const guild =
                Array.isArray(
                    guilds
                )
                    ? guilds.find(
                        item =>
                            String(
                                item.id
                            ) ===
                            guildId &&
                            Boolean(
                                item.owner
                            )
                    )
                    : null;


            if (
                !guild
            ) {

                return res
                    .status(404)
                    .json({

                        success:
                            false,

                        code:
                            "OWNERSHIP_REQUIRED",

                        message:
                            "Bu sunucunun sahibi değilsiniz veya sunucu bulunamadı.",

                        requestId:
                            req.requestId
                    });
            }


            return res.json({

                success:
                    true,

                server: {

                    id:
                        guild.id,

                    name:
                        guild.name,

                    iconUrl:
                        getGuildIconUrl(
                            guild
                        ),

                    owner:
                        true,

                    permissions:
                        String(
                            guild.permissions ||
                            "0"
                        ),

                    features:
                        Array.isArray(
                            guild.features
                        )
                            ? guild.features
                            : [],

                    modules: {

                        overview:
                            true,

                        announcements:
                            true,

                        channels:
                            true,

                        roles:
                            true,

                        moderation:
                            true,

                        logs:
                            true,

                        automation:
                            true,

                        security:
                            true,

                        ticket:
                            true,

                        voice:
                            true,

                        ai:
                            true,

                        analyzer:
                            true
                    }

                },

                requestId:
                    req.requestId
            });

        } catch (error) {

            console.error(
                "[ZYNX] Server detail:",
                error
            );


            return res
                .status(500)
                .json({

                    success:
                        false,

                    message:
                        "Sunucu detayları alınamadı.",

                    requestId:
                        req.requestId
                });
        }
    }
);


/* ==================================================================
   38 | DASHBOARD
================================================================== */

app.get(
    "/api/dashboard",
    requireAuth,
    async (
        req,
        res
    ) => {

        try {

            const userId =
                req.session.user.id;


            const subscription =
                refreshSubscription(
                    userId
                );


            const guilds =
                await discordUserRequest(
                    req,
                    "/users/@me/guilds"
                );


            const ownedCount =
                Array.isArray(
                    guilds
                )
                    ? guilds.filter(
                        guild =>
                            Boolean(
                                guild.owner
                            )
                    ).length
                    : 0;


            return res.json({

                success:
                    true,

                dashboard: {

                    user: {

                        id:
                            req.session.user.id,

                        username:
                            req.session.user.username,

                        globalName:
                            req.session.user.globalName,

                        avatarUrl:
                            req.session.user.avatarUrl
                    },

                    subscription:
                        publicSubscription(
                            subscription
                        ),

                    statistics: {

                        ownedServers:
                            ownedCount,

                        totalServersVisible:
                            ownedCount,

                        botSystems:
                            6,

                        premium:
                            isPremiumMember(
                                userId
                            ),

                        plus:
                            isPlusMember(
                                userId
                            )

                    },

                    systems: [

                        {

                            key:
                                "security",

                            name:
                                "ZYNX Security",

                            status:
                                "online"
                        },

                        {

                            key:
                                "ticket",

                            name:
                                "ZYNX Ticket",

                            status:
                                "online"
                        },

                        {

                            key:
                                "voice",

                            name:
                                "ZYNX Voice",

                            status:
                                "online"
                        },

                        {

                            key:
                                "ai",

                            name:
                                "ZYNX AI",

                            status:
                                "online"
                        },

                        {

                            key:
                                "analyzer",

                            name:
                                "ZYNX Analyzer",

                            status:
                                "beta"
                        },

                        {

                            key:
                                "plus",

                            name:
                                "ZYNX PLUS",

                            status:
                                "plus_only"
                        }

                    ],

                    platform: {

                        version:
                            CONFIG.version,

                        status:
                            "online",

                        discord:
                            "connected",

                        api:
                            "online"
                    }
                },

                requestId:
                    req.requestId
            });

        } catch (error) {

            console.error(
                "[ZYNX] Dashboard:",
                error
            );


            return res
                .status(500)
                .json({

                    success:
                        false,

                    message:
                        "Dashboard verileri alınamadı.",

                    requestId:
                        req.requestId
                });
        }
    }
);


/* ==================================================================
   39 | PROFILE
================================================================== */

app.get(
    "/api/profile",
    requireAuth,
    (
        req,
        res
    ) => {

        const user =
            req.session.user;


        const profile =
            getProfile(
                user.id
            );


        const subscription =
            refreshSubscription(
                user.id
            );


        return res.json({

            success:
                true,

            profile: {

                id:
                    user.id,

                username:
                    user.username,

                globalName:
                    user.globalName,

                avatarUrl:
                    user.avatarUrl,

                displayName:
                    profile.displayName,

                createdAt:
                    profile.createdAt,

                updatedAt:
                    profile.updatedAt
            },

            subscription:
                publicSubscription(
                    subscription
                ),

            requestId:
                req.requestId
        });
    }
);


/* ==================================================================
   40 | PROFILE UPDATE
================================================================== */

app.patch(
    "/api/profile",
    requireAuth,
    (
        req,
        res
    ) => {

        const displayName =
            clean(
                req.body?.displayName
            );


        if (
            displayName.length >
            40
        ) {

            return res
                .status(400)
                .json({

                    success:
                        false,

                    message:
                        "Görünen ad en fazla 40 karakter olabilir.",

                    requestId:
                        req.requestId
                });
        }


        const userId =
            req.session.user.id;


        const profile =
            getProfile(
                userId
            );


        profile.displayName =
            displayName ||
            null;


        profile.updatedAt =
            nowISO();


        profiles.set(
            userId,
            profile
        );


        return res.json({

            success:
                true,

            profile: {

                displayName:
                    profile.displayName,

                updatedAt:
                    profile.updatedAt
            },

            requestId:
                req.requestId
        });
    }
);


/* ==================================================================
   41 | PLANS
================================================================== */

app.get(
    "/api/plans",
    (
        req,
        res
    ) => {

        res.json({

            success:
                true,

            plans:
                PLANS,

            requestId:
                req.requestId
        });
    }
);


/* ==================================================================
   42 | SUBSCRIPTION
================================================================== */

app.get(
    "/api/subscription",
    requireAuth,
    (
        req,
        res
    ) => {

        const subscription =
            refreshSubscription(
                req.session.user.id
            );


        res.json({

            success:
                true,

            subscription:
                publicSubscription(
                    subscription
                ),

            plan:
                PLANS[
                    subscription.plan
                ],

            requestId:
                req.requestId
        });
    }
);


/* ==================================================================
   43 | FREE TRIAL
================================================================== */

app.post(
    "/api/subscription/trial",
    requireAuth,
    async (
        req,
        res
    ) => {

        const requestedPlan =
            clean(
                req.body?.plan
            ).toUpperCase();


        if (
            ![
                "PRO",
                "PLUS"
            ].includes(
                requestedPlan
            )
        ) {

            return res
                .status(400)
                .json({

                    success:
                        false,

                    message:
                        "Ücretsiz deneme yalnızca PRO veya PLUS planlarında kullanılabilir.",

                    requestId:
                        req.requestId
                });
        }


        const userId =
            req.session.user.id;


        const current =
            refreshSubscription(
                userId
            );


        if (
            current.status ===
                "trialing" ||
            current.status ===
                "active"
        ) {

            return res
                .status(409)
                .json({

                    success:
                        false,

                    code:
                        "ACTIVE_SUBSCRIPTION",

                    message:
                        "Hesabınızda zaten aktif bir abonelik bulunuyor.",

                    subscription:
                        publicSubscription(
                            current
                        ),

                    requestId:
                        req.requestId
                });
        }


        const started =
            now();


        const trialEnds =
            addDays(
                started,
                30
            );


        const subscription =
            updateSubscription(

                userId,

                {

                    plan:
                        requestedPlan,

                    status:
                        "trialing",

                    startedAt:
                        started.toISOString(),

                    trialStartedAt:
                        started.toISOString(),

                    trialEndsAt:
                        trialEnds.toISOString(),

                    currentPeriodStart:
                        started.toISOString(),

                    currentPeriodEnd:
                        trialEnds.toISOString(),

                    cancelAtPeriodEnd:
                        false,

                    canceledAt:
                        null
                }

            );


        req.session.subscription =
            subscription;


        await saveSession(
            req
        );


        return res.json({

            success:
                true,

            message:
                `${PLANS[requestedPlan].name} 30 günlük ücretsiz deneme başladı.`,

            subscription:
                publicSubscription(
                    subscription
                ),

            requestId:
                req.requestId
        });
    }
);


/* ==================================================================
   44 | CHECKOUT CREATE
================================================================== */

app.post(
    "/api/checkout/create",
    requireAuth,
    (
        req,
        res
    ) => {

        const requestedPlan =
            clean(
                req.body?.plan
            ).toUpperCase();


        if (
            ![
                "PRO",
                "PLUS"
            ].includes(
                requestedPlan
            )
        ) {

            return res
                .status(400)
                .json({

                    success:
                        false,

                    message:
                        "Geçersiz premium plan.",

                    requestId:
                        req.requestId
                });
        }


        const current =
            refreshSubscription(
                req.session.user.id
            );


        if (
            current.plan ===
                requestedPlan &&
            (
                current.status ===
                    "active" ||
                current.status ===
                    "trialing"
            )
        ) {

            return res
                .status(409)
                .json({

                    success:
                        false,

                    code:
                        "PLAN_ALREADY_ACTIVE",

                    message:
                        "Bu plan zaten aktif.",

                    subscription:
                        publicSubscription(
                            current
                        ),

                    requestId:
                        req.requestId
                });
        }


        const checkoutId =
            `chk_${randomHex(20)}`;


        const checkout = {

            id:
                checkoutId,

            userId:
                req.session.user.id,

            plan:
                requestedPlan,

            amount:
                PLANS[
                    requestedPlan
                ].price,

            currency:
                "TRY",

            status:
                "pending",

            createdAt:
                nowISO(),

            expiresAt:
                addDays(
                    now(),
                    1
                ).toISOString()
        };


        checkoutSessions.set(
            checkoutId,
            checkout
        );


        return res
            .status(201)
            .json({

                success:
                    true,

                checkout: {

                    id:
                        checkout.id,

                    plan:
                        checkout.plan,

                    amount:
                        checkout.amount,

                    currency:
                        checkout.currency,

                    status:
                        checkout.status,

                    expiresAt:
                        checkout.expiresAt
                },

                paymentProviderConnected:
                    false,

                paymentUrl:
                    null,

                message:
                    "Checkout oturumu oluşturuldu.",

                requestId:
                    req.requestId
            });
    }
);


/* ==================================================================
   45 | DEVELOPMENT SUBSCRIPTION
================================================================== */

app.post(
    "/api/subscription/dev-activate",
    requireAuth,
    async (
        req,
        res
    ) => {

        /*
            Production'da kapalı.
        */

        if (
            CONFIG.environment ===
            "production"
        ) {

            return res
                .status(404)
                .json({

                    success:
                        false,

                    message:
                        "Endpoint bulunamadı.",

                    requestId:
                        req.requestId
                });
        }


        const requestedPlan =
            clean(
                req.body?.plan
            ).toUpperCase();


        if (
            ![
                "PRO",
                "PLUS"
            ].includes(
                requestedPlan
            )
        ) {

            return res
                .status(400)
                .json({

                    success:
                        false,

                    message:
                        "PRO veya PLUS seçmelisiniz.",

                    requestId:
                        req.requestId
                });
        }


        const started =
            now();


        const end =
            addMonths(
                started,
                1
            );


        const subscription =
            updateSubscription(

                req.session.user.id,

                {

                    plan:
                        requestedPlan,

                    status:
                        "active",

                    startedAt:
                        started.toISOString(),

                    trialStartedAt:
                        null,

                    trialEndsAt:
                        null,

                    currentPeriodStart:
                        started.toISOString(),

                    currentPeriodEnd:
                        end.toISOString(),

                    cancelAtPeriodEnd:
                        false,

                    canceledAt:
                        null
                }

            );


        req.session.subscription =
            subscription;


        await saveSession(
            req
        );


        return res.json({

            success:
                true,

            development:
                true,

            message:
                `${PLANS[requestedPlan].name} geliştirme modunda aktif edildi.`,

            subscription:
                publicSubscription(
                    subscription
                ),

            requestId:
                req.requestId
        });
    }
);


/* ==================================================================
   46 | CANCEL SUBSCRIPTION
================================================================== */

app.post(
    "/api/subscription/cancel",
    requireAuth,
    async (
        req,
        res
    ) => {

        const userId =
            req.session.user.id;


        const current =
            refreshSubscription(
                userId
            );


        if (
            current.plan ===
                "FREE" ||
            (
                current.status !==
                    "active" &&
                current.status !==
                    "trialing"
            )
        ) {

            return res
                .status(400)
                .json({

                    success:
                        false,

                    message:
                        "Aktif abonelik bulunmuyor.",

                    requestId:
                        req.requestId
                });
        }


        /*
            Trial direkt iptal.
        */

        if (
            current.status ===
            "trialing"
        ) {

            const updated =
                updateSubscription(

                    userId,

                    {

                        plan:
                            "FREE",

                        status:
                            "inactive",

                        currentPeriodStart:
                            null,

                        currentPeriodEnd:
                            null,

                        cancelAtPeriodEnd:
                            false,

                        canceledAt:
                            nowISO()
                    }

                );


            req.session.subscription =
                updated;


            await saveSession(
                req
            );


            return res.json({

                success:
                    true,

                message:
                    "Ücretsiz deneme iptal edildi.",

                subscription:
                    publicSubscription(
                        updated
                    ),

                requestId:
                    req.requestId
            });
        }


        /*
            Gerçek ödeme provider'ı bağlanınca
            provider cancellation burada çağrılacak.
        */

        const updated =
            updateSubscription(

                userId,

                {

                    cancelAtPeriodEnd:
                        true,

                    canceledAt:
                        nowISO()
                }

            );


        req.session.subscription =
            updated;


        await saveSession(
            req
        );


        return res.json({

            success:
                true,

            message:
                "Abonelik dönem sonunda iptal edilecek.",

            subscription:
                publicSubscription(
                    updated
                ),

            requestId:
                req.requestId
        });
    }
);


/* ==================================================================
   47 | FEATURES
================================================================== */

app.get(
    "/api/features",
    requireAuth,
    (
        req,
        res
    ) => {

        const userId =
            req.session.user.id;


        const premium =
            isPremiumMember(
                userId
            );


        const plus =
            isPlusMember(
                userId
            );


        res.json({

            success:
                true,

            plan:
                refreshSubscription(
                    userId
                ).plan,

            features: {

                dashboard:
                    true,

                profile:
                    true,

                ownedServers:
                    true,

                botInvites:
                    true,

                advancedSecurity:
                    premium,

                advancedTicket:
                    premium,

                advancedVoice:
                    premium,

                advancedAI:
                    premium,

                analyzer:
                    true,

                analyzerAdvanced:
                    premium,

                plusBot:
                    plus,

                plusAI:
                    plus,

                aiSupport:
                    plus,

                automaticManagement:
                    plus,

                smartOptimization:
                    plus

            },

            requestId:
                req.requestId
        });
    }
);


/* ==================================================================
   48 | SUPPORT CATEGORIES
================================================================== */

app.get(
    "/api/support/categories",
    (
        req,
        res
    ) => {

        res.json({

            success:
                true,

            categories:
                Object.values(
                    SUPPORT_CATEGORIES
                ).map(
                    category => ({

                        id:
                            category.id,

                        title:
                            category.title,

                        description:
                            category.description
                    })
                ),

            requestId:
                req.requestId
        });
    }
);


/* ==================================================================
   49 | SUPPORT START
================================================================== */

app.post(
    "/api/support/start",
    requireAuth,
    (
        req,
        res
    ) => {

        const categoryId =
            clean(
                req.body?.category
            ).toLowerCase();


        const category =
            SUPPORT_CATEGORIES[
                categoryId
            ];


        if (
            !category
        ) {

            return res
                .status(400)
                .json({

                    success:
                        false,

                    message:
                        "Geçersiz destek kategorisi.",

                    requestId:
                        req.requestId
                });
        }


        const sessionId =
            `sup_${randomHex(16)}`;


        const supportSession = {

            id:
                sessionId,

            userId:
                req.session.user.id,

            category:
                category.id,

            answers:
                [],

            currentQuestion:
                0,

            createdAt:
                nowISO(),

            updatedAt:
                nowISO(),

            status:
                "collecting"
        };


        supportSessions.set(
            sessionId,
            supportSession
        );


        return res.json({

            success:
                true,

            session: {

                id:
                    sessionId,

                category: {

                    id:
                        category.id,

                    title:
                        category.title
                },

                question:
                    category.questions[0],

                questionIndex:
                    0,

                totalQuestions:
                    category.questions.length
            },

            requestId:
                req.requestId
        });
    }
);


/* ==================================================================
   50 | SUPPORT ANSWER
================================================================== */

app.post(
    "/api/support/answer",
    requireAuth,
    async (
        req,
        res
    ) => {

        const sessionId =
            clean(
                req.body?.sessionId
            );


        const answer =
            clean(
                req.body?.answer
            );


        if (
            !sessionId ||
            !answer
        ) {

            return res
                .status(400)
                .json({

                    success:
                        false,

                    message:
                        "Session ve cevap gerekli.",

                    requestId:
                        req.requestId
                });
        }


        const supportSession =
            supportSessions.get(
                sessionId
            );


        if (
            !supportSession
        ) {

            return res
                .status(404)
                .json({

                    success:
                        false,

                    message:
                        "Destek oturumu bulunamadı.",

                    requestId:
                        req.requestId
                });
        }


        /*
            Kullanıcı yalnızca kendi session'ını
            kullanabilir.
        */

        if (
            supportSession.userId !==
            req.session.user.id
        ) {

            return res
                .status(403)
                .json({

                    success:
                        false,

                    message:
                        "Bu destek oturumuna erişiminiz yok.",

                    requestId:
                        req.requestId
                });
        }


        const category =
            SUPPORT_CATEGORIES[
                supportSession.category
            ];


        supportSession.answers.push({

            question:
                category.questions[
                    supportSession.currentQuestion
                ],

            answer,

            createdAt:
                nowISO()
        });


        supportSession.currentQuestion++;


        supportSession.updatedAt =
            nowISO();


        /*
            Tüm sorular bitti.
        */

        if (
            supportSession.currentQuestion >=
            category.questions.length
        ) {

            supportSession.status =
                "ready";


            const analysis =
                await generateSupportAnalysis(
                    req,
                    supportSession
                );


            return res.json({

                success:
                    true,

                completed:
                    true,

                result:
                    analysis,

                requestId:
                    req.requestId
            });
        }


        /*
            Sonraki soru.
        */

        return res.json({

            success:
                true,

            completed:
                false,

            session: {

                id:
                    supportSession.id,

                category:
                    supportSession.category,

                question:
                    category.questions[
                        supportSession.currentQuestion
                    ],

                questionIndex:
                    supportSession.currentQuestion,

                totalQuestions:
                    category.questions.length
            },

            requestId:
                req.requestId
        });
    }
);


/* ==================================================================
   51 | SUPPORT ANALYSIS
================================================================== */

async function generateSupportAnalysis(
    req,
    supportSession
) {

    const category =
        SUPPORT_CATEGORIES[
            supportSession.category
        ];


    const joinedAnswers =
        supportSession.answers
            .map(
                item =>
                    `${item.question}\nCevap: ${item.answer}`
            )
            .join(
                "\n\n"
            );


    /*
        PLUS kullanıcısında gerçek AI provider
        tanımlıysa AI katmanına gönderiyoruz.

        Provider bağlanana kadar fallback analiz
        kullanıyoruz.
    */

    if (
        CONFIG.ai.enabled &&
        isPlusMember(
            req.session.user.id
        ) &&
        CONFIG.ai.apiUrl &&
        CONFIG.ai.apiKey
    ) {

        try {

            const aiResult =
                await callExternalAI({

                    mode:
                        "support",

                    category:
                        category.title,

                    context:
                        joinedAnswers,

                    user: {

                        username:
                            req.session.user.globalName ||
                            req.session.user.username
                    }
                });


            if (
                aiResult
            ) {

                return {

                    category:
                        category.title,

                    severity:
                        aiResult.severity ||
                        "medium",

                    summary:
                        aiResult.summary ||
                        "Sorun analiz edildi.",

                    possibleCauses:
                        Array.isArray(
                            aiResult.possibleCauses
                        )
                            ? aiResult.possibleCauses
                            : [],

                    recommendedActions:
                        Array.isArray(
                            aiResult.recommendedActions
                        )
                            ? aiResult.recommendedActions
                            : [],

                    answer:
                        aiResult.answer ||
                        "Sorun analiz edildi.",

                    ai:
                        true
                };
            }

        } catch (error) {

            console.error(
                "[ZYNX] PLUS AI support failed:",
                error
            );
        }
    }


    /*
        Fallback intelligence.
    */

    return buildFallbackSupportAnalysis(
        supportSession
    );
}


/* ==================================================================
   52 | FALLBACK SUPPORT ANALYSIS
================================================================== */

function buildFallbackSupportAnalysis(
    supportSession
) {

    const category =
        SUPPORT_CATEGORIES[
            supportSession.category
        ];


    const text =
        supportSession.answers
            .map(
                item =>
                    item.answer
            )
            .join(
                " "
            )
            .toLowerCase();


    let severity =
        "medium";


    if (
        text.includes(
            "çalışmıyor"
        ) ||
        text.includes(
            "hiç"
        ) ||
        text.includes(
            "hata"
        )
    ) {

        severity =
            "high";
    }


    const actionMap = {

        bot: [

            "İlgili botun sunucuda bulunup bulunmadığını kontrol edin.",

            "Botun Discord izinlerini kontrol edin.",

            "Sorunun hangi komutla oluştuğunu belirleyin.",

            "Bot loglarını inceleyin."

        ],

        ticket: [

            "Ticket kanalının ve kategorisinin mevcut olduğunu kontrol edin.",

            "Ticket botunun kanal oluşturma izinlerini kontrol edin.",

            "Yetkili rolünün doğru yapılandırıldığını kontrol edin."

        ],

        security: [

            "Security sisteminin aktif olduğunu kontrol edin.",

            "Botun moderasyon izinlerini kontrol edin.",

            "Son güvenlik yapılandırma değişikliklerini inceleyin."

        ],

        voice: [

            "Voice botunun ilgili ses kanalına erişimini kontrol edin.",

            "Connect ve Speak izinlerini kontrol edin.",

            "Ses sisteminin bağlantı durumunu kontrol edin."

        ],

        ai: [

            "AI sisteminin aktif olduğunu kontrol edin.",

            "AI yapılandırmasını kontrol edin.",

            "Sorunun belirli bir komut veya kanal ile sınırlı olup olmadığını kontrol edin."

        ],

        website: [

            "Sayfayı yenileyin.",

            "Oturumun devam ettiğini kontrol edin.",

            "Tarayıcı konsolunda hata olup olmadığını kontrol edin."

        ],

        billing: [

            "Aktif planınızı kontrol edin.",

            "Checkout oturumunun durumunu kontrol edin.",

            "Ödeme sağlayıcısının işlem durumunu kontrol edin."

        ],

        other: [

            "Sorunun hangi sistemden kaynaklandığını belirleyin.",

            "Sorunun tekrar oluşup oluşmadığını test edin.",

            "İlgili sistemin loglarını inceleyin."

        ]

    };


    return {

        category:
            category.title,

        severity,

        summary:
            `${category.title} kapsamında sorun bilgileri toplandı ve ilk analiz hazırlandı.`,

        possibleCauses: [

            "Eksik yapılandırma",

            "Discord izinleri",

            "Sistem bağlantısı",

            "Sunucu yapılandırması"

        ],

        recommendedActions:
            actionMap[
                supportSession.category
            ] ||
            actionMap.other,

        answer:
            "Toplanan bilgilere göre sorunun temel nedeni yapılandırma veya izin kaynaklı olabilir. İlgili ZYNX sisteminin ayarlarını kontrol edin.",

        ai:
            false
    };
}


/* ==================================================================
   53 | PLUS AI CHAT
================================================================== */

app.post(
    "/api/plus/ai/chat",
    requirePlus,
    async (
        req,
        res
    ) => {

        const message =
            clean(
                req.body?.message
            );


        if (
            !message
        ) {

            return res
                .status(400)
                .json({

                    success:
                        false,

                    message:
                        "AI mesajı boş olamaz.",

                    requestId:
                        req.requestId
                });
        }


        if (
            message.length >
            2000
        ) {

            return res
                .status(400)
                .json({

                    success:
                        false,

                    message:
                        "AI mesajı en fazla 2000 karakter olabilir.",

                    requestId:
                        req.requestId
                });
        }


        /*
            İleri aşamada burada:

                kullanıcının sunucusu
                ZYNX sistemleri
                bot durumları
                seçili guild
                izinler
                son işlemler

            AI context'ine verilecek.
        */

        const context = {

            user:

                req.session.user,

            subscription:

                publicSubscription(
                    refreshSubscription(
                        req.session.user.id
                    )
                ),

            platform:

                {

                    studio:
                        CONFIG.studio.name,

                    systems:
                        [

                            "Security",

                            "Ticket",

                            "Voice",

                            "AI",

                            "Analyzer",

                            "PLUS"

                        ]

                }

        };


        /*
            Gerçek AI provider varsa kullan.
        */

        if (
            CONFIG.ai.enabled &&
            CONFIG.ai.apiUrl &&
            CONFIG.ai.apiKey
        ) {

            try {

                const result =
                    await callExternalAI({

                        mode:
                            "plus",

                        message,

                        context
                    });


                if (
                    result
                ) {

                    return res.json({

                        success:
                            true,

                        ai: {

                            provider:
                                CONFIG.ai.provider,

                            answer:
                                result.answer ||
                                "İsteğiniz işlendi.",

                            actions:
                                Array.isArray(
                                    result.actions
                                )
                                    ? result.actions
                                    : [],

                            requiresConfirmation:
                                Boolean(
                                    result.requiresConfirmation
                                )

                        },

                        requestId:
                            req.requestId
                    });
                }

            } catch (error) {

                console.error(
                    "[ZYNX] PLUS AI provider error:",
                    error
                );
            }
        }


        /*
            Provider hazır değilse güvenli fallback.
        */

        return res.json({

            success:
                true,

            ai: {

                provider:
                    "internal",

                answer:
                    buildInternalPlusResponse(
                        message
                    ),

                actions:
                    [],

                requiresConfirmation:
                    true
            },

            requestId:
                req.requestId
        });
    }
);


/* ==================================================================
   54 | INTERNAL PLUS RESPONSE
================================================================== */

function buildInternalPlusResponse(
    message
) {

    const text =
        message.toLowerCase();


    if (
        text.includes(
            "ticket"
        )
    ) {

        return "Ticket sistemiyle ilgili bir işlem istediğini anladım. Önce hangi sunucuda ve hangi ticket ayarında işlem yapmak istediğini belirlememiz gerekiyor.";
    }


    if (
        text.includes(
            "security"
        ) ||
        text.includes(
            "güvenlik"
        ) ||
        text.includes(
            "spam"
        )
    ) {

        return "Security sistemiyle ilgili işlem istediğini anladım. İlgili sunucunun güvenlik ayarlarını inceleyip uygulanacak değişiklikleri onayından sonra hazırlayabiliriz.";
    }


    if (
        text.includes(
            "duyuru"
        )
    ) {

        return "Duyuru göndermek istediğini anladım. Önce hedef sunucuyu ve duyurunun gönderileceği kanalı belirlememiz gerekiyor.";
    }


    if (
        text.includes(
            "sunucu"
        ) &&
        (
            text.includes(
                "analiz"
            ) ||
            text.includes(
                "incele"
            )
        )
    ) {

        return "Sunucu analizi istediğini anladım. Analyzer ile sunucu yapısını, rollerini, kanallarını, izinlerini ve ZYNX yapılandırmasını inceleyebiliriz.";
    }


    return "İsteğini anladım. İşlemi gerçekleştirmeden önce hangi sunucuda çalışacağımızı ve yapılacak değişikliği netleştirip ardından gerekli ZYNX sistemine yönlendirebiliriz.";
}


/* ==================================================================
   55 | GENERIC AI PROVIDER
==================================================================

   Bu katman provider'dan bağımsız tutuldu.

   Böylece ileride gerçek AI servisini değiştirirken
   dashboard kodunu yeniden yazmamız gerekmez.

================================================================== */

async function callExternalAI(
    payload
) {

    if (
        !CONFIG.ai.apiUrl ||
        !CONFIG.ai.apiKey
    ) {

        return null;
    }


    const controller =
        new AbortController();


    const timeout =
        setTimeout(
            () =>
                controller.abort(),
            15000
        );


    try {

        const prompt =
            buildAIPrompt(
                payload
            );


        const response =
            await fetch(
                CONFIG.ai.apiUrl,
                {

                    method:
                        "POST",

                    headers: {

                        "Content-Type":
                            "application/json",

                        Authorization:
                            `Bearer ${CONFIG.ai.apiKey}`
                    },

                    body:
                        safeJSON({

                            model:
                                CONFIG.ai.model,

                            input:
                                prompt,

                            maxOutputTokens:
                                CONFIG.ai.maxOutput

                        }),

                    signal:
                        controller.signal
                }
            );


        if (
            !response.ok
        ) {

            const body =
                await response.text();


            throw new Error(
                `AI provider ${response.status}: ${body}`
            );
        }


        const raw =
            await response.text();


        const data =
            parseJSON(
                raw
            );


        if (
            !data
        ) {

            return null;
        }


        /*
            Provider response formatı daha sonra
            seçilen sağlayıcıya göre adapter ile
            normalize edilecek.
        */

        if (
            typeof data.answer ===
            "string"
        ) {

            return {

                answer:
                    data.answer,

                actions:
                    Array.isArray(
                        data.actions
                    )
                        ? data.actions
                        : [],

                requiresConfirmation:
                    Boolean(
                        data.requiresConfirmation
                    ),

                severity:
                    data.severity,

                summary:
                    data.summary,

                possibleCauses:
                    data.possibleCauses,

                recommendedActions:
                    data.recommendedActions

            };
        }


        return null;

    } catch (error) {

        if (
            error.name ===
            "AbortError"
        ) {

            throw new Error(
                "AI provider timeout."
            );
        }


        throw error;

    } finally {

        clearTimeout(
            timeout
        );
    }
}


function buildAIPrompt(
    payload
) {

    const base = `

Sen ZYNX PLUS AI sistemisin.

Kullanıcıyla Türkçe konuş.

Yanlış veya uydurma bilgi verme.

Kullanıcının isteğini anlamadan işlem gerçekleştirme.

Sunucu yönetimiyle ilgili tehlikeli veya geri dönüşü zor
işlemler için mutlaka onay iste.

ZYNX sistemleri:

- Security
- Ticket
- Voice
- AI
- Analyzer
- PLUS

Görev:

Kullanıcının isteğini anlayıp açık, profesyonel ve
bağlama uygun cevap vermek.

`;

    return (

        base +

        "\n\nMOD:\n" +
        String(
            payload.mode ||
            "plus"
        ) +

        "\n\nKULLANICI MESAJI:\n" +
        String(
            payload.message ||
            ""
        ) +

        "\n\nKONTEXT:\n" +
        safeJSON(
            payload.context ||
            {}
        )

    );
}


/* ==================================================================
   56 | ANALYZER INFO
================================================================== */

app.get(
    "/api/analyzer",
    (
        req,
        res
    ) => {

        const release =
            new Date(
                CONFIG.analyzer.launchDate
            );


        const released =
            Date.now() >=
            release.getTime();


        return res.json({

            success:
                true,

            analyzer: {

                name:
                    "ZYNX Analyzer",

                version:
                    CONFIG.analyzer.version,

                beta:
                    true,

                releaseDate:
                    CONFIG.analyzer.launchDate,

                released,

                status:
                    released
                        ? "available"
                        : "upcoming",

                title:
                    released
                        ? "ZYNX Analyzer"
                        : "ZYNX Analyzer — Yakında",

                description:
                    "Sunucunuzun yapılandırmasını, eksiklerini, izinlerini ve güvenlik risklerini analiz eden ZYNX sistemi.",

                features: [

                    "Sunucu yapılandırma analizi",

                    "Kanal ve kategori analizi",

                    "Rol analizi",

                    "Yetki analizi",

                    "Eksik yapı tespiti",

                    "Güvenlik riskleri",

                    "ZYNX sistem kontrolü",

                    "İyileştirme önerileri",

                    "Sağlık raporu",

                    "AI destekli analiz"

                ]

            },

            requestId:
                req.requestId
        });
    }
);


/* ==================================================================
   57 | ANALYZER OWNED SERVER LIST
================================================================== */

app.get(
    "/api/analyzer/servers",
    requireAuth,
    async (
        req,
        res
    ) => {

        try {

            const guilds =
                await discordUserRequest(
                    req,
                    "/users/@me/guilds"
                );


            const servers =
                Array.isArray(
                    guilds
                )
                    ? guilds
                        .filter(
                            guild =>
                                Boolean(
                                    guild.owner
                                )
                        )
                        .map(
                            guild => ({

                                id:
                                    guild.id,

                                name:
                                    guild.name,

                                iconUrl:
                                    getGuildIconUrl(
                                        guild
                                    )
                            })
                        )
                    : [];


            return res.json({

                success:
                    true,

                servers,

                count:
                    servers.length,

                analyzerReleaseDate:
                    CONFIG.analyzer.launchDate,

                requestId:
                    req.requestId
            });

        } catch (error) {

            console.error(
                "[ZYNX] Analyzer servers:",
                error
            );


            return res
                .status(500)
                .json({

                    success:
                        false,

                    message:
                        "Analyzer sunucu listesi alınamadı.",

                    requestId:
                        req.requestId
                });
        }
    }
);


/* ==================================================================
   58 | ANALYZER RUN
==================================================================

   Şu aşamada Discord'un OAuth user scope'u ile sunucunun
   tam kanal/rol ağacını değiştirmiyoruz.

   Analyzer engine'i gerçek bot/API gateway'ine bağlanacak.

   Ancak endpoint, frontend ve AI tarafının kullanacağı
   profesyonel sonuç formatını şimdiden hazırlar.

================================================================== */

app.post(
    "/api/analyzer/run",
    requireAuth,
    async (
        req,
        res
    ) => {

        const guildId =
            clean(
                req.body?.guildId
            );


        if (
            !guildId
        ) {

            return res
                .status(400)
                .json({

                    success:
                        false,

                    message:
                        "Analiz için sunucu seçmelisiniz.",

                    requestId:
                        req.requestId
                });
        }


        /*
            Analyzer'ın gerçek yayın tarihini kontrol et.
        */

        const release =
            new Date(
                CONFIG.analyzer.launchDate
            );


        if (
            Date.now() <
            release.getTime()
        ) {

            return res
                .status(423)
                .json({

                    success:
                        false,

                    code:
                        "ANALYZER_NOT_RELEASED",

                    message:
                        "ZYNX Analyzer henüz yayınlanmadı.",

                    releaseDate:
                        CONFIG.analyzer.launchDate,

                    beta:
                        true,

                    requestId:
                        req.requestId
                });
        }


        /*
            Sunucunun kullanıcıya ait olduğunu kontrol et.
        */

        const guilds =
            await discordUserRequest(
                req,
                "/users/@me/guilds"
            );


        const guild =
            Array.isArray(
                guilds
            )
                ? guilds.find(
                    item =>
                        String(
                            item.id
                        ) ===
                        guildId &&
                        Boolean(
                            item.owner
                        )
                )
                : null;


        if (
            !guild
        ) {

            return res
                .status(403)
                .json({

                    success:
                        false,

                    code:
                        "OWNERSHIP_REQUIRED",

                    message:
                        "Analyzer yalnızca sahibi olduğunuz sunucular için çalıştırılabilir.",

                    requestId:
                        req.requestId
                });
        }


        /*
            Şimdilik temel analiz iskeleti.

            Gerçek Analyzer engine bağlandığında burası
            Discord yapılandırmalarından gerçek sonuç döndürecek.
        */

        const result = {

            server: {

                id:
                    guild.id,

                name:
                    guild.name,

                iconUrl:
                    getGuildIconUrl(
                        guild
                    )
            },

            score:
                100,

            health:
                "pending",

            summary:
                "Detaylı Analyzer motoru hazırlanıyor.",

            findings: [

                {

                    id:
                        "permissions",

                    severity:
                        "info",

                    category:
                        "permissions",

                    title:
                        "Sunucu izinleri",

                    description:
                        "Sunucu sahibi olduğunuz doğrulandı.",

                    fixAvailable:
                        false
                },

                {

                    id:
                        "security",

                    severity:
                        "pending",

                    category:
                        "security",

                    title:
                        "Security analizi",

                    description:
                        "ZYNX Security analiz modülü bağlandığında detaylandırılacak.",

                    fixAvailable:
                        true
                },

                {

                    id:
                        "structure",

                    severity:
                        "pending",

                    category:
                        "structure",

                    title:
                        "Sunucu yapısı",

                    description:
                        "Kanal, kategori ve rol analizi Analyzer gateway bağlantısıyla yapılacak.",

                    fixAvailable:
                        true
                }

            ],

            recommendations: [

                "ZYNX Security sistemini etkinleştirin.",

                "Sunucu rollerini düzenli olarak gözden geçirin.",

                "Ticket sistemini yapılandırın.",

                "ZYNX AI otomasyonlarını değerlendirin."

            ],

            analyzedAt:
                nowISO(),

            analyzerVersion:
                CONFIG.analyzer.version
        };


        /*
            PLUS AI ile özet hazırlanabilirse.
        */

        if (
            isPlusMember(
                req.session.user.id
            ) &&
            CONFIG.ai.enabled &&
            CONFIG.ai.apiUrl &&
            CONFIG.ai.apiKey
        ) {

            try {

                const ai =
                    await callExternalAI({

                        mode:
                            "analyzer",

                        context:
                            result
                    });


                if (
                    ai?.summary
                ) {

                    result.aiSummary =
                        ai.summary;
                }

            } catch (error) {

                console.error(
                    "[ZYNX] Analyzer AI:",
                    error
                );
            }
        }


        return res.json({

            success:
                true,

            result,

            requestId:
                req.requestId
        });
    }
);


/* ==================================================================
   59 | BOT PUBLIC API
================================================================== */

app.get(
    "/api/bots",
    (
        req,
        res
    ) => {

        return res.json({

            success:
                true,

            bots:
                getPublicBots(),

            requestId:
                req.requestId
        });
    }
);


/* ==================================================================
   60 | PLUS BOT ACCESS
================================================================== */

app.get(
    "/api/plus/bot",
    requireAuth,
    (
        req,
        res
    ) => {

        const bot =
            ZYNX_BOTS.plus;


        const plus =
            isPlusMember(
                req.session.user.id
            );


        return res.json({

            success:
                true,

            accessible:
                plus,

            bot: {

                key:
                    bot.key,

                name:
                    bot.name,

                emoji:
                    bot.emoji,

                description:
                    bot.description,

                beta:
                    true,

                plusOnly:
                    true,

                invite:
                    plus
                        ? safeInvite(
                            bot.invite
                        )
                        : null
            },

            requestId:
                req.requestId
        });
    }
);


/* ==================================================================
   61 | SYSTEM STATUS
================================================================== */

app.get(
    "/api/status",
    (
        req,
        res
    ) => {

        const bots =
            getPublicBots();


        const botStatus = {};


        for (
            const bot
            of bots
        ) {

            const isAnalyzer =
                bot.key ===
                "analyzer";


            const isPlus =
                bot.key ===
                "plus";


            botStatus[
                bot.key
            ] = {

                name:
                    bot.name,

                emoji:
                    bot.emoji,

                status:
                    isAnalyzer
                        ? "beta"
                        : isPlus
                            ? "plus_only"
                            : bot.configured
                                ? "ready"
                                : "unconfigured",

                label:
                    isAnalyzer
                        ? "Beta / Yakında"
                        : isPlus
                            ? "PLUS"
                            : bot.configured
                                ? "Hazır"
                                : "Davet linki bekleniyor"

            };
        }


        return res.json({

            success:
                true,

            status: {

                website: {

                    status:
                        "online",

                    label:
                        "Çevrimiçi"
                },

                authentication: {

                    status:
                        "online",

                    label:
                        "Çevrimiçi"
                },

                discord: {

                    status:
                        "online",

                    label:
                        "Discord API hazır"
                },

                analyzer: {

                    status:
                        "beta",

                    label:
                        "06.09.2027 • 16:00"

                },

                bots:
                    botStatus

            },

            studio:
                CONFIG.studio,

            timestamp:
                nowISO(),

            requestId:
                req.requestId
        });
    }
);


/* ==================================================================
   62 | SUPPORT SESSION CLEANUP
================================================================== */

const supportCleanup =
    setInterval(
        () => {

            const expiration =
                Date.now() -
                (
                    60 *
                    60 *
                    1000
                );


            for (
                const [
                    id,
                    supportSession
                ]
                of supportSessions
            ) {

                const updated =
                    new Date(
                        supportSession.updatedAt
                    ).getTime();


                if (
                    updated <
                    expiration
                ) {

                    supportSessions.delete(
                        id
                    );
                }
            }

        },
        10 *
        60 *
        1000
    );


supportCleanup.unref?.();


/* ==================================================================
   63 | CHECKOUT CLEANUP
================================================================== */

const checkoutCleanup =
    setInterval(
        () => {

            const current =
                Date.now();


            for (
                const [
                    id,
                    checkout
                ]
                of checkoutSessions
            ) {

                if (
                    new Date(
                        checkout.expiresAt
                    ).getTime() <
                    current
                ) {

                    checkoutSessions.delete(
                        id
                    );
                }
            }

        },
        60 *
        1000
    );


checkoutCleanup.unref?.();


/* ==================================================================
   64 | AVATAR HELPERS
================================================================== */

function getAvatarUrl(
    user
) {

    if (
        !user?.id
    ) {

        return null;
    }


    if (
        user.avatar
    ) {

        return (
            `https://cdn.discordapp.com/avatars/` +
            `${user.id}/` +
            `${user.avatar}.png?size=256`
        );
    }


    const discriminator =
        Number(
            user.discriminator ||
            0
        );


    return (
        `https://cdn.discordapp.com/embed/avatars/` +
        `${discriminator % 5}.png`
    );
}


function getGuildIconUrl(
    guild
) {

    if (
        !guild?.id ||
        !guild.icon
    ) {

        return null;
    }


    return (
        `https://cdn.discordapp.com/icons/` +
        `${guild.id}/` +
        `${guild.icon}.png?size=256`
    );
}


/* ==================================================================
   65 | 404
================================================================== */

app.use(
    (
        req,
        res
    ) => {

        return res
            .status(404)
            .json({

                success:
                    false,

                code:
                    "NOT_FOUND",

                message:
                    "API endpoint bulunamadı.",

                path:
                    req.originalUrl,

                requestId:
                    req.requestId
            });
    }
);


/* ==================================================================
   66 | GLOBAL ERROR
================================================================== */

app.use(
    (
        error,
        req,
        res,
        next
    ) => {

        console.error(
            "\n===================================================="
        );

        console.error(
            "[ZYNX] GLOBAL ERROR"
        );

        console.error(
            "Request:",
            req.method,
            req.originalUrl
        );

        console.error(
            "Request ID:",
            req.requestId
        );

        console.error(
            error
        );

        console.error(
            "====================================================\n"
        );


        if (
            res.headersSent
        ) {

            return next(
                error
            );
        }


        return res
            .status(500)
            .json({

                success:
                    false,

                code:
                    "INTERNAL_SERVER_ERROR",

                message:
                    "Sunucu tarafında beklenmeyen bir hata oluştu.",

                requestId:
                    req.requestId
            });
    }
);


/* ==================================================================
   67 | PROCESS ERROR LOGGING
================================================================== */

process.on(
    "unhandledRejection",
    error => {

        console.error(
            "\n[ZYNX] UNHANDLED REJECTION"
        );

        console.error(
            error
        );
    }
);


process.on(
    "uncaughtException",
    error => {

        console.error(
            "\n[ZYNX] UNCAUGHT EXCEPTION"
        );

        console.error(
            error
        );
    }
);


/* ==================================================================
   68 | SERVER
================================================================== */

const server =
    app.listen(
        CONFIG.port,
        () => {

            console.log(`
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║                  Z Y N X   W E B                         ║
║                                                          ║
║                 BACKEND CORE 5.0                         ║
║                                                          ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  Version         : ${CONFIG.version}
║  Environment     : ${CONFIG.environment}
║  Port            : ${CONFIG.port}
║                                                          ║
║  Discord OAuth   : ENABLED                              ║
║  Guild Scope     : ENABLED                              ║
║  Owner Filter    : ENABLED                              ║
║  Sessions        : ENABLED                              ║
║  Dashboard       : ENABLED                              ║
║  Profile         : ENABLED                              ║
║  Subscriptions   : ENABLED                              ║
║  Free Trial      : ENABLED                              ║
║  Checkout        : ENABLED                              ║
║  Support AI      : ENABLED                              ║
║  PLUS AI         : ENABLED                              ║
║  Analyzer        : BETA                                  ║
║  PLUS Bot        : BETA                                  ║
║                                                          ║
║                  STATUS: ONLINE                         ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
            `);


            console.log(
                "\n[ZYNX] Bot invite configuration:"
            );


            for (
                const bot
                of getPublicBots()
            ) {

                console.log(

                    `  ${bot.emoji} ${bot.name}` +
                    ` | Invite: ${
                        bot.configured
                            ? "OK"
                            : "MISSING"
                    }`

                );
            }


            console.log(
                "\n[ZYNX] TR LIFE STUDIOS"
            );

            console.log(
                `[ZYNX] ${CONFIG.studio.role}`
            );


            console.log(
                "\n[ZYNX] Backend ready.\n"
            );
        }
    );


/* ==================================================================
   69 | HTTP SERVER SETTINGS
================================================================== */

server.keepAliveTimeout =
    65000;


server.headersTimeout =
    66000;


/* ==================================================================
   70 | GRACEFUL SHUTDOWN
================================================================== */

let shuttingDown =
    false;


async function shutdown(
    signal
) {

    if (
        shuttingDown
    ) {

        return;
    }


    shuttingDown =
        true;


    console.log(
        `\n[ZYNX] ${signal} received.`
    );


    clearInterval(
        supportCleanup
    );


    clearInterval(
        checkoutCleanup
    );


    server.close(
        error => {

            if (
                error
            ) {

                console.error(
                    "[ZYNX] Server close error:",
                    error
                );


                process.exit(
                    1
                );


                return;
            }


            console.log(
                "[ZYNX] Backend stopped safely."
            );


            process.exit(
                0
            );
        }
    );


    setTimeout(
        () => {

            console.error(
                "[ZYNX] Forced shutdown."
            );


            process.exit(
                1
            );

        },
        10000
    ).unref();
}


process.on(
    "SIGINT",
    () =>
        shutdown(
            "SIGINT"
        )
);


process.on(
    "SIGTERM",
    () =>
        shutdown(
            "SIGTERM"
        )
);


/* ==================================================================
                           END OF FILE
================================================================== */