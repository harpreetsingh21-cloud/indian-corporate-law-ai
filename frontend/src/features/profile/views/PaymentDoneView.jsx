import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { CheckCircle2, XCircle, Clock, Loader2, ArrowLeft, ShieldCheck, Smartphone, RotateCcw } from 'lucide-react'
import { LegalBuddyLogo } from '../../../shared/ui/LegalBuddyLogo'
import { useUIStore } from '../../../shared/store/uiStore'
import { authAPI } from '../../../shared/utils/api'

const fadeUp = (delay = 0) => ({
    initial: { opacity: 0, y: 12 },
    animate: { opacity: 1, y: 0, transition: { delay, duration: 0.4, ease: [0.16, 1, 0.3, 1] } },
})

const SCREENS = {
    checking: {
        icon: Loader2,
        spin: true,
        circle: 'from-gray-400 to-gray-500 shadow-gray-500/30',
        title: 'Checking your payment…',
        text: 'Please wait while we confirm the result with PhonePe.',
    },
    success: {
        icon: CheckCircle2,
        circle: 'from-orange-500 to-amber-500 shadow-orange-500/30',
        title: 'Payment successful',
        text: 'Your Pro plan is now active. Go back to the LegalBuddy tab to continue.',
    },
    failed: {
        icon: XCircle,
        circle: 'from-red-500 to-rose-500 shadow-red-500/30',
        title: 'Payment failed',
        text: 'No money was taken for this order. Go back to LegalBuddy and try again.',
    },
    pending: {
        icon: Clock,
        circle: 'from-yellow-500 to-amber-500 shadow-yellow-500/30',
        title: 'Payment pending',
        text: 'PhonePe has not confirmed this payment yet. We will keep checking for a minute.',
    },
}

export default function PaymentDoneView() {
    useUIStore()
    const orderId = new URLSearchParams(window.location.search).get('order_id')
    const [state, setState] = useState(orderId ? 'checking' : 'pending')
    const [expires, setExpires] = useState(null)

    useEffect(() => {
        if (!orderId) return
        let tries = 0
        let stopped = false

        const check = async () => {
            tries += 1
            try {
                const res = await authAPI.paymentStatus(orderId)
                if (stopped) return
                if (res.state === 'COMPLETED') {
                    setExpires(res.expires)
                    setState('success')
                    return
                }
                if (res.state === 'FAILED') {
                    setState('failed')
                    return
                }
                setState('pending')
            } catch {
                if (!stopped) setState('pending')
            }
            if (!stopped && tries < 20) setTimeout(check, 3000)
        }

        check()
        return () => { stopped = true }
    }, [orderId])

    const screen = SCREENS[state]
    const Icon = screen.icon

    const closeTab = () => {
        window.close()
        setTimeout(() => { window.location.href = '/' }, 300)
    }

    return (
        <div className="min-h-screen w-full flex items-center justify-center p-4 bg-gray-50 dark:bg-black relative overflow-hidden font-poppins transition-colors duration-300">
            <div className="absolute rounded-full pointer-events-none blur-[120px] bg-orange-500/10 dark:bg-orange-500/8 w-[550px] h-[550px] -top-32 -left-20" />
            <div className="absolute rounded-full pointer-events-none blur-[120px] bg-orange-500/8 dark:bg-orange-500/5 w-[500px] h-[500px] -bottom-32 -right-20" />

            <motion.div
                initial={{ opacity: 0, y: 20, scale: 0.97 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
                className="relative z-10 w-full max-w-md rounded-[28px] border border-gray-200 dark:border-neutral-800 bg-white dark:bg-neutral-950 shadow-2xl overflow-hidden"
            >
                <div className="flex items-center gap-3 px-6 py-4 border-b border-gray-200 dark:border-neutral-800 bg-gray-50 dark:bg-[#070707]">
                    <LegalBuddyLogo size={34} withGlow={true} className="shrink-0" />
                    <div>
                        <div className="font-outfit text-base font-extrabold text-gray-900 dark:text-white tracking-tight">LegalBuddy</div>
                        <div className="text-[10px] text-orange-500 font-semibold uppercase tracking-wider">Secure Payment</div>
                    </div>
                </div>

                <div className="px-8 py-10 flex flex-col items-center text-center">
                    <motion.div
                        key={state}
                        initial={{ scale: 0, rotate: -20 }}
                        animate={{ scale: 1, rotate: 0 }}
                        transition={{ type: 'spring', stiffness: 260, damping: 18 }}
                        className={`w-20 h-20 rounded-full bg-gradient-to-br ${screen.circle} shadow-lg flex items-center justify-center mb-6`}
                    >
                        <Icon size={40} className={`text-white ${screen.spin ? 'animate-spin' : ''}`} />
                    </motion.div>

                    <motion.h1 key={`t-${state}`} {...fadeUp(0.1)} className="font-outfit text-2xl font-extrabold text-gray-900 dark:text-white tracking-tight mb-2">
                        {screen.title}
                    </motion.h1>

                    <motion.p key={`p-${state}`} {...fadeUp(0.15)} className="text-sm text-gray-500 dark:text-neutral-400 leading-relaxed mb-6">
                        {screen.text}
                    </motion.p>

                    <motion.div {...fadeUp(0.2)} className="w-full flex items-center gap-3 p-3 rounded-xl bg-orange-500/5 border border-orange-500/20 text-left mb-6">
                        <div className="w-9 h-9 rounded-lg bg-orange-500/10 border border-orange-500/20 flex items-center justify-center shrink-0">
                            <Smartphone size={16} className="text-orange-500" />
                        </div>
                        <div className="min-w-0">
                            <div className="text-xs font-bold text-gray-900 dark:text-white font-outfit">
                                {state === 'success' && expires ? `Pro until ${new Date(expires).toLocaleDateString()}` : 'Paid via PhonePe'}
                            </div>
                            <div className="text-[11px] text-gray-500 dark:text-neutral-400 truncate">
                                {orderId ? `Order ${orderId}` : 'No order id found in the link'}
                            </div>
                        </div>
                    </motion.div>

                    <motion.button
                        {...fadeUp(0.25)}
                        onClick={closeTab}
                        className={`w-full py-3 rounded-xl text-white font-outfit font-bold text-sm flex items-center justify-center gap-2 shadow-md transition-all cursor-pointer ${state === 'failed' ? 'bg-red-500 hover:bg-red-600 shadow-red-500/30' : 'bg-orange-500 hover:bg-orange-600 shadow-orange-500/30'
                            }`}
                    >
                        {state === 'failed' ? <RotateCcw size={15} /> : <ArrowLeft size={15} />}
                        {state === 'failed' ? 'Back to LegalBuddy to retry' : 'Close this tab'}
                    </motion.button>

                    <motion.div {...fadeUp(0.3)} className="flex items-center gap-1.5 mt-5 text-[11px] text-gray-400 dark:text-neutral-500">
                        <ShieldCheck size={13} className="text-green-500" /> Verified by our server with PhonePe · Test mode
                    </motion.div>
                </div>
            </motion.div>
        </div>
    )
}