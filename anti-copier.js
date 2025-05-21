// Anti-Website Copier Protection
// Copyright (c) 2024 - BOZO Security Team
// Version 2.0.0 - Advanced Multi-Layer Security System

// ========== الطبقة الأولى - التحقق الكلاسيكي والمراقبة ==========

// IP و GeoIP التحقق - سيتم تخزين سجل للزوار
let securityLog = {
    ip: "Unknown",
    userAgent: navigator.userAgent,
    timestamp: new Date().toISOString(),
    suspiciousActivity: [],
    threatLevel: 0 // 0 = عادي, 1 = مشبوه, 2 = خطر
};

// محاولة الحصول على عنوان IP (تحتاج لخدمة خارجية)
async function getVisitorIP() {
    try {
        const response = await fetch('https://api.ipify.org?format=json');
        const data = await response.json();
        securityLog.ip = data.ip;
        
        // يمكنك إضافة فحص GeoIP هنا
        checkIPRisk(data.ip);
    } catch (e) {
        // إضافة علامة مشبوهة إذا فشل الاتصال بخدمة IP
        securityLog.suspiciousActivity.push("Failed IP detection");
        incrementThreatLevel(1);
    }
}

// التحقق من مخاطر IP (مثال، يمكن ربطه بقاعدة بيانات خارجية)
function checkIPRisk(ip) {
    // تم تعطيل الحظر المبكر للـ IP
    return false;
}

// التحقق من الهيدرز المشبوهة
function checkSuspiciousHeaders() {
    // التحقق من هيدر المتصفح
    const userAgent = navigator.userAgent.toLowerCase();
    const suspiciousAgents = [
        'fetch', 'bot', 'crawler', 'spider', 'curl', 'wget', 'postman',
        'python', 'go-http', 'java', 'ruby', 'request', 'axios'
    ];
    
    for (const agent of suspiciousAgents) {
        if (userAgent.includes(agent)) {
            securityLog.suspiciousActivity.push(`Suspicious user agent: ${agent}`);
            incrementThreatLevel(1);
        }
    }
    
    // التحقق من وجود هيدرز عادة ما تستخدم في الهجمات
    function checkHeadersOnRequest() {
        const originalFetch = window.fetch;
        window.fetch = function(resource, options) {
            if (options && options.headers) {
                const headers = options.headers;
                const suspiciousHeaders = ['x-forwarded-for', 'proxy', 'via'];
                
                for (const header in headers) {
                    if (suspiciousHeaders.includes(header.toLowerCase())) {
                        securityLog.suspiciousActivity.push(`Suspicious header: ${header}`);
                        incrementThreatLevel(1);
                    }
                }
            }
            return originalFetch.apply(this, arguments);
        };
    }
    
    checkHeadersOnRequest();
}

// التحقق من الكوكيز غير الطبيعية
function checkSuspiciousCookies() {
    const cookies = document.cookie;
    
    // تحقق من وجود علامات في الكوكيز
    const suspiciousPatterns = ['<script', 'onload', 'onerror', '%3c', 'exec'];
    
    for (const pattern of suspiciousPatterns) {
        if (cookies.toLowerCase().includes(pattern)) {
            securityLog.suspiciousActivity.push("Suspicious cookie pattern detected");
            incrementThreatLevel(1);
        }
    }
    
    // عدد الكوكيز كبير جدًا
    if (cookies.split(';').length > 50) {
        securityLog.suspiciousActivity.push("Unusually high number of cookies");
        incrementThreatLevel(1);
    }
}

// FingerprintJS للتحقق من هوية الجهاز
function setupDeviceFingerprinting() {
    // تنفيذ بسيط لبصمة الجهاز
    const deviceId = fingerprintDevice();
    securityLog.deviceId = deviceId;
    
    // تحقق من التخزين المحلي للكشف عن تغييرات الجهاز
    const storedDeviceId = localStorage.getItem('device_security_id');
    
    if (storedDeviceId && storedDeviceId !== deviceId) {
        securityLog.suspiciousActivity.push("Device fingerprint changed");
        incrementThreatLevel(1);
    }
    
    localStorage.setItem('device_security_id', deviceId);
}

// إنشاء بصمة الجهاز
function fingerprintDevice() {
    const components = [
        navigator.userAgent,
        navigator.language,
        screen.colorDepth,
        screen.width + 'x' + screen.height,
        new Date().getTimezoneOffset(),
        !!window.sessionStorage,
        !!window.localStorage,
        !!window.indexedDB,
        !!window.openDatabase,
        navigator.cpuClass || '',
        navigator.platform || '',
        navigator.doNotTrack || ''
    ];
    
    // استخدم خوارزمية بسيطة لإنشاء معرّف
    return btoa(components.join('###')).slice(0, 32);
}

// مراقبة سرعة التصفح (Bot Detection)
function monitorBrowsingSpeed() {
    const interactionEvents = ['click', 'mousemove', 'keydown', 'scroll'];
    const maxEventsPerSecond = 30;
    let eventCounter = 0;
    let lastResetTime = Date.now();
    
    interactionEvents.forEach(eventType => {
        document.addEventListener(eventType, () => {
            eventCounter++;
            const now = Date.now();
            
            // تحقق من عدد الأحداث في الثانية
            if (now - lastResetTime > 1000) {
                // إعادة ضبط العداد كل ثانية
                lastResetTime = now;
                
                // إذا كانت سرعة التفاعل عالية جدًا (بوت محتمل)
                if (eventCounter > maxEventsPerSecond) {
                    securityLog.suspiciousActivity.push(`High interaction rate: ${eventCounter}/sec`);
                    incrementThreatLevel(1);
                }
                
                eventCounter = 0;
            }
        });
    });
}

// تحليل السلوك (Behavioral Analysis)
function analyzeBehavior() {
    // مراقبة النمط السلوكي
    const pageLoadTime = Date.now();
    let firstClick = true;
    let firstScroll = true;
    let clickCount = 0;
    let scrollCount = 0;
    let moveCount = 0;
    
    // مراقبة الضغطات
    document.addEventListener('click', function(e) {
        clickCount++;
        
        // تحقق من السرعة الأولى للتفاعل (البوتات عادة تضغط بسرعة بعد تحميل الصفحة)
        if (firstClick) {
            firstClick = false;
            const timeSinceLoad = Date.now() - pageLoadTime;
            
            // أقل من 500 مللي ثانية مشبوه
            if (timeSinceLoad < 500) {
                securityLog.suspiciousActivity.push("Suspiciously fast first click");
                incrementThreatLevel(1);
            }
        }
        
        // تحقق من تكرار الضغط على نفس الموقع
        const clickSpots = [];
        if (clickSpots.some(spot => 
            Math.abs(spot.x - e.clientX) < 5 && 
            Math.abs(spot.y - e.clientY) < 5)) {
            securityLog.suspiciousActivity.push("Repetitive clicking pattern");
            incrementThreatLevel(1);
        }
        
        clickSpots.push({x: e.clientX, y: e.clientY});
        if (clickSpots.length > 10) clickSpots.shift(); // احتفظ بآخر 10 ضغطات
    });
    
    // مراقبة التمرير
    document.addEventListener('scroll', function() {
        scrollCount++;
        
        if (firstScroll) {
            firstScroll = false;
            const timeSinceLoad = Date.now() - pageLoadTime;
            
            // تمرير سريع جدًا بعد التحميل
            if (timeSinceLoad < 200) {
                securityLog.suspiciousActivity.push("Suspiciously fast first scroll");
                incrementThreatLevel(1);
            }
        }
    });
    
    // مراقبة حركة الماوس
    document.addEventListener('mousemove', function(e) {
        moveCount++;
    });
    
    // تحليل دوري للسلوك
    setInterval(function() {
        // تحقق من نسبة الضغطات إلى حركة الماوس (البوتات عادة لديها نسبة أعلى)
        if (moveCount > 0 && clickCount/moveCount > 0.5) {
            securityLog.suspiciousActivity.push("Unusual click to movement ratio");
            incrementThreatLevel(1);
        }
        
        // تحقق من عدم وجود حركة ماوس مع وجود تمرير (محتمل استخدام سكريبت تمرير)
        if (moveCount === 0 && scrollCount > 5) {
            securityLog.suspiciousActivity.push("Scrolling without mouse movement");
            incrementThreatLevel(1);
        }
        
        // إعادة ضبط العدادات للتحليل التالي
        clickCount = 0;
        scrollCount = 0;
        moveCount = 0;
    }, 10000); // تحليل كل 10 ثواني
}

// أداة الكشف عن DevTools
function detectDevTools() {
    // تخفيف الحماية - فقط سجل محاولات فتح DevTools دون حظر مباشر
    window.addEventListener('resize', function() {
        const widthThreshold = window.outerWidth - window.innerWidth > 160;
        const heightThreshold = window.outerHeight - window.innerHeight > 160;
        
        if (widthThreshold || heightThreshold) {
            securityLog.suspiciousActivity.push("DevTools detected via window size");
            incrementThreatLevel(1); // تخفيض مستوى التهديد من 2 إلى 1
        }
    });
    
    // إزالة الفحص باستخدام debugger لتجنب المشاكل
    // تعليق الكود القديم
    /*
    setInterval(function() {
        const startTime = performance.now();
        debugger;
        const endTime = performance.now();
        
        if (endTime - startTime > 50) {
            securityLog.suspiciousActivity.push("DevTools detected via debugger delay");
            incrementThreatLevel(2);
            triggerSecurityResponse();
        }
    }, 1000);
    */
    
    // تخفيف حماية مفاتيح التطوير
    document.addEventListener('keydown', function(e) {
        // تسجيل المحاولة فقط دون حظر
        if (e.key === 'F12' || 
            (e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74 || e.keyCode === 67)) ||
            (e.ctrlKey && e.shiftKey && e.keyCode === 75) ||
            (e.metaKey && e.altKey && (e.keyCode === 73 || e.keyCode === 74 || e.keyCode === 67))) {
            securityLog.suspiciousActivity.push("DevTools shortcut detected");
            incrementThreatLevel(1); // تخفيض مستوى التهديد
        }
    });
}

// == وظائف الإدارة والاستجابة ==

// زيادة مستوى التهديد
function incrementThreatLevel(amount) {
    // تخفيف معدل زيادة مستوى التهديد
    securityLog.threatLevel += (amount * 0.5); // تخفيض معدل الزيادة بالنصف
    
    // زيادة العتبة قبل اتخاذ إجراء
    if (securityLog.threatLevel >= 12) { // زيادة العتبة من 3 إلى 12
        triggerSecurityResponse();
    }
}

// تفعيل استجابة الأمان اعتمادًا على مستوى التهديد
function triggerSecurityResponse() {
    // تخفيف مستوى الحماية بشكل كبير
    if (securityLog.threatLevel >= 15) { // زيادة العتبة من 8 إلى 15
        // مستوى تهديد عالي جدًا - حظر المستخدم مباشرة
        blockUser("high_threat");
    } else if (securityLog.threatLevel >= 10) { // زيادة العتبة من 5 إلى 10
        // مستوى تهديد متوسط - تشغيل الوضع الدفاعي
        activateDefenseMode();
    } else {
        // راقب المستخدم لكن دون تشغيل الحماية الكاملة بعد
        monitorUserActivity();
    }
    
    // سجل الحدث دائمًا
    logSecurityEvent();
}

// تنشيط وضع الدفاع (ستتم إضافة التفاصيل لاحقًا في الطبقة الثانية)
function activateDefenseMode() {
    console.log("Defensive mode activated at level: " + securityLog.threatLevel);
    initializeChaosMode();
}

// العفو حظر المستخدم
function blockUser(reason) {
    // حفظ سبب الحظر في التخزين المحلي للمتصفح
    localStorage.setItem('blocked_reason', reason);
    localStorage.setItem('security_log', JSON.stringify(securityLog));
    
    // التوجيه إلى صفحة الحظر
    window.location.href = 'blocked.html?reason=' + reason;
}

// تسجيل حدث الأمان
function logSecurityEvent() {
    // في الإصدار الحقيقي، أرسل البيانات إلى الخادم
    // للأغراض التوضيحية، نخزنها فقط في التخزين المحلي
    localStorage.setItem('security_event_' + Date.now(), JSON.stringify(securityLog));
}

// مراقبة نشاط المستخدم المشبوه
function monitorUserActivity() {
    // زيادة المراقبة ولكن دون إجراء مباشر
    console.log("User under heightened monitoring");
}

// == تنفيذ نظام الحماية من موقع ويب كوبي (محسّن) ==
function detectWebsiteCopiersAndScrapers() {
    // تم تعطيل الفحص المبكر
    return false;
}

// Check for browser automation tools like Selenium and Puppeteer
function detectAutomationTools() {
    // تم تعطيل الفحص المبكر
    return false;
}

// Rate limiting to detect scrapers
let requestCounter = 0;
const requestLimit = 200; // زيادة الحد من 120 إلى 200
const requestTimeframe = 10000; // 10 seconds

function trackRequest() {
    requestCounter++;
    
    if (requestCounter > requestLimit) {
        window.location.href = 'blocked.html?reason=ratelimit';
        return false;
    }
    
    setTimeout(() => {
        requestCounter--;
    }, requestTimeframe);
    
    return true;
}

// Add honeypot elements
function addHoneypotElements() {
    // Create hidden container
    const honeypotContainer = document.createElement('div');
    honeypotContainer.style.height = '1px';
    honeypotContainer.style.width = '1px';
    honeypotContainer.style.position = 'absolute';
    honeypotContainer.style.left = '-9999px';
    honeypotContainer.style.overflow = 'hidden';
    honeypotContainer.id = 'user-content-data';
    
    // Add fake important-looking content
    honeypotContainer.innerHTML = `
        <div class="user-data content-main" id="user-data-list">
            <a href="/login.php" class="login-link">Login</a>
            <a href="/admin.php" class="admin-link">Admin Panel</a>
            <a href="/download/source.zip" class="source-link">Download Source</a>
            <a href="/api/keys.json" class="api-link">API Keys</a>
        </div>
    `;
    
    // Append to document
    document.body.appendChild(honeypotContainer);
    
    // Add event listeners to detect clicks on honeypot links
    const honeyLinks = honeypotContainer.querySelectorAll('a');
    honeyLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            console.log('Honeypot link clicked: ' + link.href);
            window.location.href = 'blocked.html?reason=honeypot';
        });
    });
}

// Function to obfuscate content to make scraping harder
function obfuscateContent() {
    // Split text in key elements to make scraping harder
    document.querySelectorAll('h1, h2, h3, p.important, .sensitive-data').forEach(element => {
        if (element.innerHTML.includes('<')) return; // Skip if already has HTML

        const originalText = element.textContent;
        element.setAttribute('data-text', btoa(originalText));
        
        // Replace with spans for each character with a mix of text and properties
        let newContent = '';
        for (let i = 0; i < originalText.length; i++) {
            const char = originalText[i];
            newContent += `<span class="c" data-i="${i}">${char}</span>`;
        }
        
        element.innerHTML = newContent;
    });
    
    // Add decoy classes and data attributes
    document.querySelectorAll('div, section').forEach(el => {
        // Add random data attributes to elements
        if (Math.random() > 0.7) {
            el.setAttribute('data-seq', Math.floor(Math.random() * 1000));
            
            // Add some decoy classes with random names
            const randomClass = 'c-' + Math.random().toString(36).substring(2, 8);
            el.classList.add(randomClass);
        }
    });
}

// Add 'nofollow' to external links
function protectExternalLinks() {
    document.querySelectorAll('a[href^="http"]').forEach(link => {
        link.setAttribute('rel', 'nofollow noopener noreferrer');
    });
}

// Detect if the site is being framed
function preventFraming() {
    if (window.self !== window.top) {
        // Page is in an iframe
        window.top.location.href = window.self.location.href;
        document.body.innerHTML = "⛔ Security Alert: Unauthorized framing detected.";
    }
}

// ========== الطبقة الرابعة - نظام التشويش والإغلاق القاتل ==========

function initializeChaosMode() {
    let chaosActivated = false;
    
    function generateChaosContent() {
        let chaosHTML = '';
        // توليد محتوى عشوائي كثيف
        for (let i = 0; i < 10000; i++) {
            chaosHTML += `
                <div class="chaos-element" style="position:fixed;top:${Math.random() * 100}%;left:${Math.random() * 100}%;z-index:999999;">
                    ${Math.random().toString(36).repeat(1000)}
                </div>
            `;
        }
        return chaosHTML;
    }
    
    function createMemoryPressure() {
        const arrays = [];
        try {
            // إنشاء ضغط على الذاكرة
            for (let i = 0; i < 1000; i++) {
                const arr = new Array(1000000).fill('X'.repeat(1000));
                arrays.push(arr);
                // إضافة تأثيرات مرئية مكثفة
                document.body.style.filter = `blur(${i}px) contrast(${i * 100}%)`;
            }
        } catch (e) {
            console.warn('Memory pressure applied');
        }
    }
    
    function startVisualChaos() {
        if (chaosActivated) return;
        chaosActivated = true;
        
        // إنشاء طبقة التشويش البصري
        const chaosLayer = document.createElement('div');
        chaosLayer.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            z-index: 999999;
            background: black;
            overflow: hidden;
        `;
        
        // إضافة محتوى التشويش
        chaosLayer.innerHTML = generateChaosContent();
        document.body.appendChild(chaosLayer);
        
        // تشغيل حلقة لا نهائية من التأثيرات
        let chaosInterval = setInterval(() => {
            // تحديث المحتوى بشكل مستمر
            chaosLayer.innerHTML += generateChaosContent();
            // إضافة تأثيرات CSS مكثفة
            document.body.style.transform = `scale(${Math.random() * 10}) rotate(${Math.random() * 360}deg)`;
            
            // إنشاء عناصر DOM بشكل مستمر
            for (let i = 0; i < 100; i++) {
                const div = document.createElement('div');
                div.style.cssText = `
                    position: fixed;
                    width: 100vw;
                    height: 100vh;
                    background: rgb(${Math.random() * 255},${Math.random() * 255},${Math.random() * 255});
                    filter: blur(${Math.random() * 20}px);
                    animation: chaos ${Math.random() * 0.1}s infinite;
                    z-index: ${999999 + i};
                `;
                document.body.appendChild(div);
            }
            
            // تشغيل ضغط الذاكرة
            createMemoryPressure();
            
            // محاولة تعطيل أدوات المطور
            debugger;
            
            // إعادة تحميل الصفحة بشكل متكرر
            if (Math.random() > 0.5) {
                window.location.reload();
            }
        }, 100);
        
        // محاولة منع إيقاف الحلقة
        window.addEventListener('beforeunload', (e) => {
            e.returnValue = '';
            startVisualChaos();
        });
    }
    
    // تحسين كشف DevTools
    function enhancedDevToolsDetection() {
        // Method 1: حجم النافذة
        window.addEventListener('resize', () => {
            if (window.outerWidth - window.innerWidth > 160 || window.outerHeight - window.innerHeight > 160) {
                startVisualChaos();
            }
        });
        
        // Method 2: تتبع التوقيت
        setInterval(() => {
            const start = performance.now();
            debugger;
            const end = performance.now();
            if (end - start > 100) {
                startVisualChaos();
            }
        }, 1000);
        
        // Method 3: مراقبة console.log
        const originalLog = console.log;
        console.log = function() {
            startVisualChaos();
            return originalLog.apply(this, arguments);
        };
        
        // Method 4: كشف تغييرات DOM
        const observer = new MutationObserver(() => {
            if (document.querySelector('div.chrome-devtools')) {
                startVisualChaos();
            }
        });
        observer.observe(document.documentElement, { childList: true, subtree: true });
    }
    
    // تفعيل الحماية المحسنة
    enhancedDevToolsDetection();
}

// ========== نظام التشويش والإغلاق القاتل ==========
function initializeChaosProtection() {
    let isProtectionActive = false;

    function generateRandomContent() {
        return Array(1000).fill(0).map(() => 
            Math.random().toString(36).repeat(100)
        ).join('');
    }

    function startChaosMode() {
        if (isProtectionActive) return;
        isProtectionActive = true;

        // إنشاء طبقة التشويش
        const chaosContainer = document.createElement('div');
        chaosContainer.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: black;
            z-index: 999999;
            overflow: hidden;
        `;
        document.body.appendChild(chaosContainer);

        // بدء حلقة التشويش
        let chaosInterval = setInterval(() => {
            // إضافة محتوى عشوائي
            for (let i = 0; i < 100; i++) {
                const chaosElement = document.createElement('div');
                chaosElement.innerHTML = generateRandomContent();
                chaosContainer.appendChild(chaosElement);
            }

            // تأثيرات بصرية مكثفة
            document.body.style.transform = `scale(${Math.random() * 5})`;
            document.body.style.filter = `blur(${Math.random() * 20}px)`;

            // إعادة تحميل الصفحة عشوائياً
            if (Math.random() > 0.7) {
                window.location.reload();
            }
        }, 100);

        // منع إغلاق الصفحة
        window.onbeforeunload = () => {
            return '';
        };
    }

    // تحسين كشف DevTools
    const enhancedDetection = () => {
        // كشف عن طريق حجم النافذة
        window.addEventListener('resize', () => {
            if (window.outerWidth - window.innerWidth > 160) {
                startChaosMode();
            }
        });

        // كشف عن طريق التوقيت
        setInterval(() => {
            const start = performance.now();
            debugger;
            const end = performance.now();
            if (end - start > 100) {
                startChaosMode();
            }
        }, 1000);
    };

    // تفعيل الحماية
    enhancedDetection();
}

// تحديث دالة تفعيل وضع الدفاع
const originalActivateDefense = activateDefenseMode;
activateDefenseMode = function() {
    originalActivateDefense();
    initializeChaosProtection();
};

// تفعيل الحماية عند تحميل الصفحة
document.addEventListener('DOMContentLoaded', function() {
    if (window.location.pathname.includes('evidence-dashboard.html')) {
        initializeChaosProtection();
    }
});

// ========== نظام التشفير والحماية المتقدمة للصفحة المحظورة ==========
function initializeEncryptedCrashPage() {
    // دالة التشفير الأساسية
    function encryptString(str) {
        return btoa(
            encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
                function toSolidBytes(match, p1) {
                    return String.fromCharCode('0x' + p1);
                })
        ).split('').reverse().join('');
    }

    // دالة فك التشفير
    function decryptString(str) {
        return decodeURIComponent(
            atob(str.split('').reverse().join(''))
            .split('').map(function(c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join('')
        );
    }

    // توليد شيفرة عشوائية
    function generateEncryptionKey() {
        return Array(32).fill(0).map(() => 
            Math.random().toString(36).charAt(2)
        ).join('');
    }

    // إنشاء محتوى مشفر
    function createEncryptedContent() {
        const key = generateEncryptionKey();
        const timestamp = Date.now();
        
        // تشفير البيانات الحساسة
        const encryptedData = {
            key: encryptString(key),
            timestamp: encryptString(timestamp.toString()),
            userAgent: encryptString(navigator.userAgent),
            screenData: encryptString(`${window.screen.width}x${window.screen.height}`),
            threatLevel: encryptString(securityLog.threatLevel.toString())
        };

        // إنشاء كود HTML مشفر
        const encryptedHTML = `
            <div class="encrypted-container" data-key="${encryptedData.key}">
                <div class="encrypted-layer" data-timestamp="${encryptedData.timestamp}">
                    <div class="security-mesh" data-ua="${encryptedData.userAgent}">
                        <div class="protection-grid" data-screen="${encryptedData.screenData}">
                            ${Array(100).fill(0).map(() => 
                                `<div class="encrypted-cell">${encryptString(Math.random().toString(36))}</div>`
                            ).join('')}
                        </div>
                    </div>
                </div>
            </div>
        `;

        return { encryptedHTML, key };
    }

    // تفعيل الحماية المشفرة
    function activateEncryptedProtection() {
        const { encryptedHTML, key } = createEncryptedContent();
        
        // إنشاء طبقة الحماية المشفرة
        const protectionLayer = document.createElement('div');
        protectionLayer.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: #000;
            z-index: 999999;
            overflow: hidden;
            opacity: 0.95;
        `;
        protectionLayer.innerHTML = encryptedHTML;
        
        // إضافة تأثيرات مشفرة
        const style = document.createElement('style');
        style.textContent = `
            .encrypted-container {
                width: 100%;
                height: 100%;
                position: relative;
                animation: encryptedPulse 0.5s infinite;
            }
            .encrypted-layer {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                display: grid;
                grid-template-columns: repeat(10, 1fr);
                gap: 2px;
            }
            .security-mesh {
                width: 100%;
                height: 100%;
                position: relative;
            }
            .protection-grid {
                display: flex;
                flex-wrap: wrap;
                justify-content: space-between;
                align-items: center;
                padding: 20px;
            }
            .encrypted-cell {
                font-family: monospace;
                color: #0f0;
                font-size: 10px;
                white-space: nowrap;
                overflow: hidden;
                animation: cellScramble 0.1s infinite;
            }
            @keyframes encryptedPulse {
                0% { transform: scale(1); }
                50% { transform: scale(1.02); }
                100% { transform: scale(1); }
            }
            @keyframes cellScramble {
                0% { opacity: 0.5; }
                50% { opacity: 1; }
                100% { opacity: 0.5; }
            }
        `;
        document.head.appendChild(style);
        document.body.appendChild(protectionLayer);

        // تفعيل حلقة التشفير
        let encryptionInterval = setInterval(() => {
            // تحديث المحتوى المشفر
            const cells = document.querySelectorAll('.encrypted-cell');
            cells.forEach(cell => {
                cell.textContent = encryptString(Math.random().toString(36));
            });

            // إضافة تأثيرات عشوائية مشفرة
            protectionLayer.style.transform = `matrix(
                ${1 + Math.random() * 0.1}, ${Math.random() * 0.1},
                ${Math.random() * 0.1}, ${1 + Math.random() * 0.1},
                ${Math.random() * 10}, ${Math.random() * 10}
            )`;

            // تشفير وإعادة تشفير البيانات
            const newKey = generateEncryptionKey();
            protectionLayer.setAttribute('data-key', encryptString(newKey));
        }, 50);

        // منع إيقاف التشفير
        window.addEventListener('beforeunload', (e) => {
            e.returnValue = encryptString('SECURITY_BREACH_DETECTED');
            activateEncryptedProtection();
        });

        // تفعيل الحماية القصوى
        setTimeout(() => {
            window.location.href = 'blocked.html?reason=' + encryptString('security_breach');
        }, 3000);
    }

    return {
        activate: activateEncryptedProtection,
        encrypt: encryptString,
        decrypt: decryptString
    };
}

// تحديث دالة الحظر لتستخدم النظام المشفر
const originalBlockUser = blockUser;
blockUser = function(reason) {
    const encryptedCrash = initializeEncryptedCrashPage();
    encryptedCrash.activate();
    originalBlockUser(encryptedCrash.encrypt(reason));
};

// تحديث دالة تفعيل وضع الدفاع
const originalDefenseMode = activateDefenseMode;
activateDefenseMode = function() {
    originalDefenseMode();
    const encryptedCrash = initializeEncryptedCrashPage();
    if (securityLog.threatLevel >= 10) {
        encryptedCrash.activate();
    }
};

// تفعيل الحماية عند تحميل الصفحة
document.addEventListener('DOMContentLoaded', function() {
    if (window.location.pathname.includes('evidence-dashboard.html')) {
        initializeEncryptedCrashPage();
    }
}); 