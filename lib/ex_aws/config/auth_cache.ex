defmodule ExAws.Config.AuthCache do
  use GenServer

  @moduledoc false

  # http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, :ok, opts)
  end

  def get(config) do
    case :ets.lookup(__MODULE__, :aws_instance_auth) do
      [{:aws_instance_auth, auth_config}] -> auth_config
      [] -> GenServer.call(__MODULE__, {:refresh_config, config}, 30_000)
    end
  end
  def get(profile, expiration, retrieve_awscli \\ true) do
    case :ets.lookup(__MODULE__, :awscli) do
      [{:awscli, auth_config}] -> auth_config
      [] -> GenServer.call(__MODULE__, {:refresh_awscli_config, profile, expiration, retrieve_awscli}, 30_000)
    end
  end

  ## Callbacks

  def init(:ok) do
    ets = :ets.new(__MODULE__, [:named_table, read_concurrency: true])
    {:ok, ets}
  end

  def handle_call({:refresh_config, config}, _from, ets) do
    auth = refresh_config(config, ets)
    {:reply, auth, ets}
  end
  def handle_call({:refresh_awscli_config, profile, expiration, retrieve_awscli}, _from, ets) do
    auth = refresh_awscli_config(profile, expiration, retrieve_awscli, ets)
    {:reply, auth, ets}
  end

  def handle_info({:refresh_config, config}, ets) do
    refresh_config(config, ets)
    {:noreply, ets}
  end
  def handle_info({:refresh_awscli_config, profile, expiration, retrieve_awscli}, ets) do
    refresh_awscli_config(profile, expiration, retrieve_awscli, ets)
    {:noreply, ets}
  end

  def refresh_awscli_config(profile, expiration, retrieve_awscli, ets) do
    local_auth =  ExAws.CredentialsIni.security_credentials(profile)
    :ets.insert(ets, {:awscli, local_auth})

    auth = if retrieve_awscli do
      op = ExAws.STS.assume_role("arn:aws:iam::647886759881:role/silo-xa-roles-ue1-DevAdmin", "default_session")

      {:ok, result} =  ExAws.Operation.perform(op, ExAws.Config.new(op.service, [], false))
      remote_auth = %{
        access_key_id: result[:body][:access_key_id],
        secret_access_key: result[:body][:secret_access_key],
        security_token: result[:body][:session_token],
        expiration: result[:body][:expiration]
      }

      :ets.insert(ets, {:awscli, remote_auth})
      remote_auth
    else
      local_auth
    end

    Process.send_after(self(), {:refresh_awscli_config, profile, expiration}, expiration)
    auth
  end

  def refresh_config(config, ets) do
    auth = ExAws.InstanceMeta.security_credentials(config)
    :ets.insert(ets, {:aws_instance_auth, auth})
    Process.send_after(self(), {:refresh_config, config}, refresh_in(auth[:expiration]))
    auth
  end

  def refresh_in(expiration) do
    expiration = expiration |> ExAws.Utils.iso_z_to_secs
    time_to_expiration = expiration - ExAws.Utils.now_in_seconds
    refresh_in = time_to_expiration - 5 * 60 # check five mins prior to expiration
    max(0, refresh_in * 1000) # check now if we should have checked in the past
  end

end
