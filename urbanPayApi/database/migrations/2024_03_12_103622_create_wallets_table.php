<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('wallets', function (Blueprint $table) {
            $table->id();
            $table->string('user_id');
            $table->foreignId('wallet_id');
            $table->foreignId('transaction_id');
            $table->string('account_name');
            $table->string('account_email');
            $table->string('account_number');
            $table->string('currency');
            $table->string('bank_name');
            $table->string('balance');
            $table->string('account_reference');
            $table->string('status')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('wallets');
    }
};
