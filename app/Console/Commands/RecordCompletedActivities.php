<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\AktivitasPribadi;
use App\Models\RiwayatAktivitas;

class RecordCompletedActivities extends Command
{
    // Nama dan deskripsi command
    protected $signature = 'activities:record';
    protected $description = 'Record completed personal activities and reset their status';

    public function handle()
    {
        // Ambil semua aktivitas yang is_completed = true
        $completedActivities = AktivitasPribadi::where('is_completed', true)->get();

        foreach ($completedActivities as $activity) {
            // Masukkan data ke tabel RiwayatAktivitas
            RiwayatAktivitas::create([
                'id_pasien' => $activity->id_pasien,
                'id_aktivitas_positif' => $activity->id_aktivitas_positif,
            ]);

            // Reset nilai is_completed ke false
            $activity->update(['is_completed' => false]);
        }

        // Informasi di terminal
        $this->info('Completed activities have been recorded, and statuses have been reset.');
    }
}
