package org.scamhunter.guard

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context

/** Refreshes the reported-numbers list once a day, on an unmetered network (Wi-Fi). */
class ListJob : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        Thread {
            val ok = try { NumberList.download(this); true } catch (e: Exception) { false }
            jobFinished(params, !ok)
        }.start()
        return true
    }

    override fun onStopJob(params: JobParameters) = true

    companion object {
        private const val ID = 4242
        fun schedule(ctx: Context) {
            val js = ctx.getSystemService(JobScheduler::class.java)
            if (js.getPendingJob(ID) != null) return
            js.schedule(JobInfo.Builder(ID, ComponentName(ctx, ListJob::class.java))
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_UNMETERED)
                .setPeriodic(24 * 60 * 60 * 1000L)
                .setPersisted(true)
                .build())
        }
    }
}
